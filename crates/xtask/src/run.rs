//! Оркестрация прогона: подготовка, последовательное исполнение, отчёт, диff.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Context as _;

use crate::baseline::{self, Divergence};
use crate::cli::E2eArgs;
use crate::exec::{Delivery, ExecDeps, ExecOptions, Executor, HELPERS_VAR};
use crate::interact::{ConsoleOperator, Operator, OperatorError, Verdict};
use crate::profile::{FixturesEntry, Profile};
use crate::provenance::{ArtifactProvenance, Provenance};
use crate::redact::Redactor;
use crate::registry::{self, Registry};
use crate::report::{self, CaseResult, RunReport};
use crate::stand::{OpCli, StandConfig, StandError};
use crate::vars::Vars;
use crate::{artifacts, driver, repo_root};

/// Код возврата, когда прогон не состоялся: стенд не описан.
pub const EXIT_NO_STAND: i32 = 2;

/// Куда кладётся проверяемый пакет; кейсам доступен как `{{package}}`.
///
/// Всё, что раннер везёт в окружение, живёт под `/opt/tessera-e2e`: один корень
/// даёт teardown'у единственное место для уборки.
const REMOTE_PACKAGE: &str = "/opt/tessera-e2e/pkg/tessera.deb";

/// Прогон реестра.
///
/// # Ошибки
///
/// Всё, что делает прогон невозможным: нечитаемый реестр, недоступное
/// хранилище секретов, отсутствующий пакет, несобранный драйвер.
pub fn e2e(args: &E2eArgs) -> anyhow::Result<i32> {
    let e2e_root = repo_root().join("tests").join("e2e");

    let stand_path = match &args.stand {
        Some(path) => path.clone(),
        None => StandConfig::default_path()?,
    };
    let stand = match StandConfig::load(&stand_path) {
        Ok(stand) => stand,
        Err(StandError::Missing { path }) => {
            eprintln!("Нет файла параметров стенда {}.\n", path.display());
            eprintln!("Создайте его по образцу:\n");
            println!("{}", crate::stand::SAMPLE);
            return Ok(EXIT_NO_STAND);
        }
        Err(err) => return Err(err.into()),
    };

    let profile = Profile::load(&e2e_root.join("profiles"), &args.profile)?;
    if let Some(description) = &profile.description {
        println!("профиль {}: {description}", profile.name);
    }

    let fixtures = profile.fixture_deliveries(&repo_root());

    let mut vars = prepare_vars(&profile, &stand)?;
    // Кейс не должен знать ни путь к пакету на машине оператора, ни раскладку
    // окружения: он видит только подстановки. Профиль и стенд сильнее: заданное
    // ими место каталога и есть то, куда поедет доставка.
    for entry in &fixtures {
        if let Some(var) = &entry.var {
            if vars.plain(var).is_none() {
                vars.insert_plain(var.clone(), entry.target.clone());
            }
        }
    }
    vars.insert_plain("package", REMOTE_PACKAGE);
    let vars = vars;
    let (secret_vars, redactor) = announce_redaction(&vars);

    let cases_dirs = if args.cases_dir.is_empty() {
        vec![e2e_root.join("cases")]
    } else {
        args.cases_dir.clone()
    };
    let registry = Registry::load(&cases_dirs)?;
    for warning in registry.warnings() {
        eprintln!("ВНИМАНИЕ: {warning}");
    }

    let package = Provenance::of_package(
        &stand.package.deb,
        stand.package.source.as_deref(),
        stand.package.commit.as_deref(),
    )?;
    if !package.is_established() {
        eprintln!(
            "ВНИМАНИЕ: провенанс пакета не установлен — коммит сборки подтвердить нечем; \
             прогон не годится как evidence релиза."
        );
    }

    // Провенанс дополнительных артефактов считается до пересоздания окружения:
    // отсутствующий файл — ошибка описания стенда, и узнать о ней нужно раньше
    // первого кейса. Заодно отчёт получает контрольные суммы всего, что
    // приедет в окружение помимо пакета.
    let stand_artifacts = artifact_provenance(&stand)?;
    announce_artifacts(&stand_artifacts);

    let deliveries = plan_deliveries(&fixtures, &stand, &vars);
    // Проверка до пересоздания окружения: отсутствующий каталог-источник — это
    // ошибка описания стенда, и узнать о ней нужно раньше, чем сборка образа
    // и первый кейс потратят минуты.
    check_sources(&deliveries)?;

    let interrupt = Arc::new(AtomicBool::new(false));
    // Перехват сигнала нужен ради teardown: прерванный прогон не должен
    // оставлять окружение в промежуточном состоянии.
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&interrupt))
        .context("перехват SIGINT")?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&interrupt))
        .context("перехват SIGTERM")?;

    let runs_root = e2e_root.join("runs");
    warn_if_suspect(&runs_root);

    let driver = prepare_driver(&profile, &stand, &vars, args.recreate, &interrupt)?;

    let started_at = now();
    let run_dir = report::run_dir(&runs_root, &today(), &profile.name, &package);
    let results = execute(
        args,
        &registry,
        &profile,
        driver.as_ref(),
        vars,
        &redactor,
        &run_dir.join("artifacts"),
        deliveries,
        &interrupt,
    );

    let report = RunReport {
        started_at,
        finished_at: now(),
        profile: profile.name.clone(),
        environment: driver.describe(),
        package: package.clone(),
        stand_artifacts,
        non_interactive: args.non_interactive,
        keep_on_failure: args.keep_on_failure,
        interrupted: interrupt.load(Ordering::SeqCst),
        secret_vars,
        cases: results,
    };
    report::write(&run_dir, &report, &redactor).context("запись отчёта")?;
    println!("\nотчёт: {}", run_dir.display());
    update_suspect_marker(&runs_root, &report);

    compare_with_baseline(args, &report, &package)
}

/// Собирает драйвер окружения и, если просили, пересоздаёт его.
fn prepare_driver(
    profile: &Profile,
    stand: &StandConfig,
    vars: &Vars,
    recreate: bool,
    interrupt: &Arc<AtomicBool>,
) -> anyhow::Result<Box<dyn driver::CommandDriver>> {
    let driver = driver::build(
        profile,
        stand,
        &repo_root(),
        stand_root(vars),
        Arc::clone(interrupt),
    )?;
    if recreate {
        driver.recreate().context("пересоздание окружения")?;
    }
    Ok(driver)
}

/// Корень стенда в целевом окружении: откуда исполняются команды кейсов.
///
/// Считается от каталога хелперов, а не задаётся отдельным полем: исполнитель
/// ищет скрипты подготовки по той же переменной, и разъедься эти два места,
/// кейс запускался бы не оттуда, где лежит его материал. Контейнерный профиль
/// величину не берёт — там рабочий каталог задаёт `WORKDIR` образа.
fn stand_root(vars: &Vars) -> Option<&str> {
    vars.plain(HELPERS_VAR).map(driver::remote_parent)
}

/// Что раннер везёт в окружение перед первым действием подготовки.
///
/// Цели берутся из тех же переменных, которые видит кейс: разъедься доставка
/// с подстановкой, кейс искал бы пакет и фикстуры не там, куда их положили.
fn plan_deliveries(fixtures: &[FixturesEntry], stand: &StandConfig, vars: &Vars) -> Vec<Delivery> {
    let mut deliveries = vec![Delivery::new(
        "пакет",
        stand.package.deb.clone(),
        vars.plain("package").unwrap_or(REMOTE_PACKAGE).to_owned(),
    )];
    deliveries.extend(fixtures.iter().map(|entry| {
        let target = entry
            .var
            .as_deref()
            .and_then(|var| vars.plain(var))
            .unwrap_or(entry.target.as_str());
        let what = match &entry.var {
            Some(var) => format!("фикстуры {var}"),
            None => format!("фикстуры {target}"),
        };
        Delivery::new(what, entry.source.clone(), target.to_owned())
    }));
    // Артефакты стенда едут последними: их цели заданы абсолютными путями и от
    // раскладки раннера не зависят.
    deliveries.extend(stand.artifacts.iter().map(|artifact| {
        Delivery::new(
            format!("артефакт стенда {}", artifact.target),
            artifact.path.clone(),
            artifact.target.clone(),
        )
        .with_mode(artifact.mode.to_string())
    }));
    deliveries
}

/// Называет вслух всё, что поедет в окружение помимо пакета.
fn announce_artifacts(artifacts: &[ArtifactProvenance]) {
    if artifacts.is_empty() {
        return;
    }
    let targets: Vec<&str> = artifacts
        .iter()
        .map(|artifact| artifact.target.as_str())
        .collect();
    eprintln!("помимо пакета в окружение везётся: {}", targets.join(", "));
}

/// Считает происхождение дополнительных артефактов стенда.
///
/// # Ошибки
///
/// Отсутствующий или нечитаемый файл-источник любого из артефактов.
fn artifact_provenance(stand: &StandConfig) -> anyhow::Result<Vec<ArtifactProvenance>> {
    stand
        .artifacts
        .iter()
        .map(|artifact| {
            ArtifactProvenance::of_file(
                &artifact.path,
                &artifact.target,
                &artifact.mode.to_string(),
            )
            .map_err(anyhow::Error::from)
        })
        .collect()
}

/// Проверяет, что везти есть что.
///
/// # Ошибки
///
/// Отсутствующий источник любой из доставок.
fn check_sources(deliveries: &[Delivery]) -> anyhow::Result<()> {
    for delivery in deliveries {
        anyhow::ensure!(
            delivery.local.exists(),
            "доставка ({}): источник {} не найден",
            delivery.what,
            delivery.local.display()
        );
    }
    Ok(())
}

/// Собирает переменные прогона, разрешая ссылки на секреты до первого кейса:
/// недоступность хранилища должна выглядеть как проблема стенда, а не как
/// провал аутентификации.
fn prepare_vars(profile: &Profile, stand: &StandConfig) -> anyhow::Result<Vars> {
    let mut vars = Vars::new();
    for (name, value) in &profile.vars {
        vars.insert_plain(name.clone(), value.clone());
    }
    let stand_vars = crate::stand::resolve_vars(&stand.vars, &OpCli)
        .context("разрешение ссылок на секреты из stand.toml")?;
    // Значения стенда перекрывают профильные: лаборатория знает про себя больше,
    // чем описание типа окружения в git.
    vars.absorb(stand_vars);
    Ok(vars)
}

/// Последовательно исполняет отобранные кейсы.
#[expect(
    clippy::too_many_arguments,
    reason = "состояние прогона собирается в вызывающем; отдельная структура здесь ничего не упростит"
)]
fn execute(
    args: &E2eArgs,
    registry: &Registry,
    profile: &Profile,
    driver: &dyn crate::driver::CommandDriver,
    vars: Vars,
    redactor: &Redactor,
    artifacts_dir: &Path,
    deliveries: Vec<Delivery>,
    interrupt: &Arc<AtomicBool>,
) -> Vec<CaseResult> {
    let mut console = ConsoleOperator;
    let mut silent = SilentOperator;
    let operator: &mut dyn Operator = if args.non_interactive {
        &mut silent
    } else {
        &mut console
    };
    let options = ExecOptions {
        non_interactive: args.non_interactive,
        keep_on_failure: args.keep_on_failure,
    };
    let collector = artifacts::FileCollector::new(artifacts_dir.to_path_buf(), driver, redactor);
    let deps = ExecDeps {
        driver,
        profile,
        operator,
        collector: &collector,
    };
    let mut executor = Executor::new(deps, vars, options, deliveries, Arc::clone(interrupt));

    let mut results: Vec<CaseResult> = Vec::new();
    let mut current_suite: Option<&str> = None;
    for (suite, case) in registry.cases() {
        if !registry::matches_filter(suite, case, args.filter.as_deref()) {
            continue;
        }
        if current_suite != Some(suite.suite.as_str()) {
            current_suite = Some(suite.suite.as_str());
            match &suite.description {
                Some(description) => println!("\n== {} — {description}", suite.suite),
                None => println!("\n== {}", suite.suite),
            }
        }
        let result = executor.run_case(suite, case);
        println!(
            "{:<7} {:<12} {}",
            result.status.as_str(),
            result.id,
            result.title
        );
        results.push(result);
        if interrupt.load(Ordering::SeqCst) {
            eprintln!("прогон прерван сигналом, оставшиеся кейсы не исполнялись");
            break;
        }
    }
    results
}

/// Считает расхождение с baseline и, если попросили, обновляет его.
///
/// # Ошибки
///
/// Ошибки чтения и записи файлов baseline.
fn compare_with_baseline(
    args: &E2eArgs,
    report: &RunReport,
    package: &Provenance,
) -> anyhow::Result<i32> {
    let roots: Vec<PathBuf> = report
        .cases
        .iter()
        .map(|case| case.registry_root.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut baselines = baseline::load_for_roots(&roots)?;

    let mut divergences: Vec<Divergence> = Vec::new();
    for (root, baseline) in &baselines {
        divergences.extend(baseline.diff(&subset(report, root), &report.profile));
    }
    print_diff(&divergences);

    if args.update_baseline {
        let version = package_version(&package.path);
        for (root, baseline) in &mut baselines {
            let refused =
                baseline.update(&subset(report, root), &report.profile, &today(), &version);
            baseline.save(&baseline::baseline_path(root))?;
            for line in refused {
                eprintln!("в baseline не записано — {line}");
            }
        }
    }

    Ok(baseline::exit_code(&report.cases, &divergences))
}

fn subset(report: &RunReport, root: &Path) -> Vec<CaseResult> {
    report
        .cases
        .iter()
        .filter(|case| case.registry_root == root)
        .cloned()
        .collect()
}

fn print_diff(divergences: &[Divergence]) {
    if divergences.is_empty() {
        println!("расхождений с baseline нет");
        return;
    }
    println!("\nрасхождения с baseline:");
    for divergence in divergences {
        println!("  {}", divergence.describe());
    }
}

/// Оператор, которого нет: в неинтерактивном прогоне до паузы дойти нельзя,
/// такие кейсы отсекаются раньше статусом `BLOCKED`.
struct SilentOperator;

impl Operator for SilentOperator {
    fn pause(
        &mut self,
        _text: &str,
        _capture: Option<&str>,
    ) -> Result<(Verdict, Option<String>), OperatorError> {
        Err(OperatorError::Eof)
    }
}

/// Собирает вычистку секретов и называет переменные, чьи значения из отчёта
/// вырезаются: оператор должен знать, почему в отчёте стоит заглушка.
fn announce_redaction(vars: &Vars) -> (Vec<String>, Redactor) {
    let secret_vars: Vec<String> = vars.secret_names().into_iter().map(str::to_owned).collect();
    let redactor = Redactor::new(vars.secret_values());
    if !redactor.is_empty() {
        eprintln!(
            "значения переменных {} получены по ссылкам на хранилище и вычищаются из отчёта",
            secret_vars.join(", ")
        );
    }
    (secret_vars, redactor)
}

fn now() -> String {
    chrono::Local::now()
        .format("%Y-%m-%d %H:%M:%S%:z")
        .to_string()
}

fn today() -> String {
    chrono::Local::now().format("%Y-%m-%d").to_string()
}

/// Версия пакета из имени файла `tessera_<версия>_<арх>.deb`.
fn package_version(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.split('_').nth(1))
        .unwrap_or("неизвестна")
        .to_owned()
}

fn suspect_marker(runs_root: &Path) -> PathBuf {
    runs_root.join("SUSPECT")
}

fn warn_if_suspect(runs_root: &Path) {
    if let Ok(text) = std::fs::read_to_string(suspect_marker(runs_root)) {
        eprintln!(
            "ВНИМАНИЕ: предыдущий прогон оставил окружение подозрительным.\n{}",
            text.trim()
        );
    }
}

fn update_suspect_marker(runs_root: &Path, report: &RunReport) {
    let marker = suspect_marker(runs_root);
    if report.has_failed_teardown() {
        let ids: Vec<&str> = report
            .cases
            .iter()
            .filter(|case| case.teardown.is_failed())
            .map(|case| case.id.as_str())
            .collect();
        let written = std::fs::create_dir_all(runs_root).and_then(|()| {
            std::fs::write(
                marker,
                format!(
                    "{}: teardown не отработал в кейсах: {}\n",
                    report.finished_at,
                    ids.join(", ")
                ),
            )
        });
        if let Err(err) = written {
            eprintln!("не отметить окружение как подозрительное: {err}");
        }
    } else if let Err(err) = std::fs::remove_file(marker) {
        if err.kind() != std::io::ErrorKind::NotFound {
            eprintln!("не снять отметку подозрительного окружения: {err}");
        }
    }
}

#[cfg(test)]
// Тестам разрешено падать на нарушенных инвариантах: это и есть их способ
// сообщить о проблеме.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn profile() -> Profile {
        toml::from_str(
            r#"
name = "ubuntu-container"
driver = "docker"

[docker]
container = "c"
image = "i"
"#,
        )
        .unwrap()
    }

    fn stand() -> StandConfig {
        toml::from_str(
            r#"
[package]
deb = "/art/tessera_0.4.0_amd64.deb"
"#,
        )
        .unwrap()
    }

    fn multi_fixture_profile() -> Profile {
        toml::from_str(
            r#"
name = "ubuntu-container"
driver = "docker"

[[fixtures]]
source = "crates/tessera_core/tests/fixtures"
target = "/opt/tessera-e2e/fixtures"
var = "fixtures"

[[fixtures]]
source = "tests/fixtures/roles"
target = "/opt/tessera-e2e/roles"
var = "roles"

[docker]
container = "c"
image = "i"
"#,
        )
        .unwrap()
    }

    #[test]
    fn deliveries_default_to_the_runner_layout() {
        let mut vars = Vars::new();
        vars.insert_plain("fixtures", crate::profile::DEFAULT_FIXTURES_TARGET);
        vars.insert_plain("package", REMOTE_PACKAGE);

        let fixtures = profile().fixture_deliveries(&repo_root());
        let deliveries = plan_deliveries(&fixtures, &stand(), &vars);
        assert_eq!(deliveries.len(), 2);
        assert_eq!(
            deliveries[0].local,
            PathBuf::from("/art/tessera_0.4.0_amd64.deb")
        );
        assert_eq!(deliveries[0].remote, REMOTE_PACKAGE);
        assert_eq!(
            deliveries[1].local,
            repo_root().join(crate::profile::DEFAULT_FIXTURES_SOURCE)
        );
        assert_eq!(
            deliveries[1].remote,
            crate::profile::DEFAULT_FIXTURES_TARGET
        );
    }

    #[test]
    fn every_fixture_source_of_the_profile_gets_its_own_delivery() {
        let fixtures = multi_fixture_profile().fixture_deliveries(&repo_root());
        let deliveries = plan_deliveries(&fixtures, &stand(), &Vars::new());
        assert_eq!(deliveries.len(), 3);
        assert_eq!(
            deliveries[1].local,
            repo_root().join("crates/tessera_core/tests/fixtures")
        );
        assert_eq!(deliveries[1].remote, "/opt/tessera-e2e/fixtures");
        assert_eq!(
            deliveries[2].local,
            repo_root().join("tests/fixtures/roles")
        );
        assert_eq!(deliveries[2].remote, "/opt/tessera-e2e/roles");
        // Груз называется именем подстановки: сообщение о сбое доставки должно
        // указывать на конкретный каталог, а не на «фикстуры» вообще.
        assert_eq!(deliveries[2].what, "фикстуры roles");
    }

    #[test]
    fn a_stand_that_moves_the_fixtures_moves_the_delivery_with_them() {
        // Кейс подставляет {{fixtures}} и {{roles}}; вези раннер каталог по
        // своему адресу, кейс искал бы материал не там, где он лежит.
        let mut vars = Vars::new();
        vars.insert_plain("fixtures", "/srv/e2e/fixtures");
        vars.insert_plain("roles", "/srv/e2e/roles");

        let fixtures = multi_fixture_profile().fixture_deliveries(&repo_root());
        let deliveries = plan_deliveries(&fixtures, &stand(), &vars);
        assert_eq!(deliveries[1].remote, "/srv/e2e/fixtures");
        assert_eq!(deliveries[2].remote, "/srv/e2e/roles");
    }

    #[test]
    fn a_missing_fixture_source_is_reported_before_the_run() {
        let fixtures = multi_fixture_profile().fixture_deliveries(Path::new("/нет-такого-корня"));
        let deliveries = plan_deliveries(&fixtures, &stand(), &Vars::new());
        let err = check_sources(&deliveries).unwrap_err().to_string();
        // Первым в списке идёт пакет, и его в тесте тоже нет: важно, что прогон
        // не стартует, а сообщение называет и груз, и путь.
        assert!(err.contains("источник"), "{err}");
        assert!(err.contains("tessera_0.4.0_amd64.deb"), "{err}");
    }

    #[test]
    fn a_present_source_passes_the_check() {
        let fixtures = multi_fixture_profile().fixture_deliveries(&repo_root());
        let deliveries = plan_deliveries(&fixtures, &stand(), &Vars::new());
        // Пакет из stand.toml в дереве репозитория не лежит — проверяем только
        // каталоги фикстур, которые обязаны существовать.
        check_sources(&deliveries[1..]).unwrap();
    }

    fn stand_with_artifacts(path: &Path) -> StandConfig {
        toml::from_str(&format!(
            r#"
[package]
deb = "/art/tessera_0.4.0_amd64.deb"

[[artifacts]]
path = "{}"
target = "/usr/local/bin/issuer"
mode = "0755"
"#,
            path.display()
        ))
        .unwrap()
    }

    #[test]
    fn extra_stand_artifacts_are_delivered_with_their_mode() {
        let fixtures = profile().fixture_deliveries(&repo_root());
        let stand = stand_with_artifacts(Path::new("/build/issuer"));
        let deliveries = plan_deliveries(&fixtures, &stand, &Vars::new());
        // Пакет, фикстуры профиля и артефакт стенда.
        assert_eq!(deliveries.len(), 3);
        let artifact = &deliveries[2];
        assert_eq!(artifact.local, PathBuf::from("/build/issuer"));
        assert_eq!(artifact.remote, "/usr/local/bin/issuer");
        assert_eq!(artifact.mode.as_deref(), Some("0755"));
        // Сообщение о сбое доставки должно называть конкретный артефакт.
        assert_eq!(artifact.what, "артефакт стенда /usr/local/bin/issuer");
    }

    #[test]
    fn a_stand_without_the_section_delivers_exactly_what_it_did_before() {
        let fixtures = profile().fixture_deliveries(&repo_root());
        let deliveries = plan_deliveries(&fixtures, &stand(), &Vars::new());
        assert_eq!(deliveries.len(), 2);
        assert!(deliveries.iter().all(|delivery| delivery.mode.is_none()));
        assert!(artifact_provenance(&stand()).unwrap().is_empty());
    }

    #[test]
    fn a_missing_artifact_source_is_reported_before_the_run() {
        let dir = tempfile::tempdir().unwrap();
        let stand = stand_with_artifacts(&dir.path().join("нет-такого-issuer"));
        let err = artifact_provenance(&stand).unwrap_err().to_string();
        assert!(err.contains("/usr/local/bin/issuer"), "{err}");
        assert!(err.contains("не найден"), "{err}");
    }

    #[test]
    fn a_delivered_artifact_is_recorded_with_its_checksum() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("issuer");
        std::fs::write(&source, b"issuer").unwrap();

        let recorded = artifact_provenance(&stand_with_artifacts(&source)).unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].target, "/usr/local/bin/issuer");
        assert_eq!(recorded[0].mode, "0755");
        assert_eq!(recorded[0].size, 6);
        assert_eq!(recorded[0].sha256.len(), 64);
    }

    #[test]
    fn package_version_comes_from_the_file_name() {
        assert_eq!(
            package_version(Path::new("/art/tessera_0.4.0_amd64.deb")),
            "0.4.0"
        );
        assert_eq!(
            package_version(Path::new("/art/произвольное.deb")),
            "неизвестна"
        );
    }
}
