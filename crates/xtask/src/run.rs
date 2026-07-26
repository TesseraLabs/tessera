//! Оркестрация прогона: подготовка, последовательное исполнение, отчёт, диff.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Context as _;

use crate::baseline::{self, Divergence};
use crate::cli::E2eArgs;
use crate::exec::{Delivery, ExecDeps, ExecOptions, Executor};
use crate::interact::{ConsoleOperator, Operator, OperatorError, Verdict};
use crate::profile::Profile;
use crate::provenance::Provenance;
use crate::redact::Redactor;
use crate::registry::{self, Registry};
use crate::report::{self, CaseResult, RunReport};
use crate::stand::{OpCli, StandConfig, StandError};
use crate::vars::Vars;
use crate::{artifacts, driver};

/// Код возврата, когда прогон не состоялся: стенд не описан.
pub const EXIT_NO_STAND: i32 = 2;

/// Куда кладётся проверяемый пакет; кейсам доступен как `{{package}}`.
///
/// Всё, что раннер везёт в окружение, живёт под `/opt/tessera-e2e`: один корень
/// даёт teardown'у единственное место для уборки.
const REMOTE_PACKAGE: &str = "/opt/tessera-e2e/pkg/tessera.deb";

/// Куда кладутся фикстуры; кейсам доступны как `{{fixtures}}`. Значение можно
/// перекрыть переменной профиля или стенда — тогда доставка едет туда же, куда
/// смотрят кейсы.
const REMOTE_FIXTURES: &str = "/opt/tessera-e2e/fixtures";

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

    let mut vars = prepare_vars(&profile, &stand)?;
    // Кейс не должен знать ни путь к пакету на машине оператора, ни раскладку
    // окружения: он видит только подстановки.
    if vars.plain("fixtures").is_none() {
        vars.insert_plain("fixtures", REMOTE_FIXTURES);
    }
    vars.insert_plain("package", REMOTE_PACKAGE);
    let vars = vars;
    let secret_vars: Vec<String> = vars.secret_names().into_iter().map(str::to_owned).collect();
    let redactor = Redactor::new(vars.secret_values());
    if !redactor.is_empty() {
        eprintln!(
            "значения переменных {} получены по ссылкам на хранилище и вычищаются из отчёта",
            secret_vars.join(", ")
        );
    }

    let cases_dirs = if args.cases_dir.is_empty() {
        vec![e2e_root.join("cases")]
    } else {
        args.cases_dir.clone()
    };
    let registry = Registry::load(&cases_dirs)?;

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

    let interrupt = Arc::new(AtomicBool::new(false));
    // Перехват сигнала нужен ради teardown: прерванный прогон не должен
    // оставлять окружение в промежуточном состоянии.
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&interrupt))
        .context("перехват SIGINT")?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&interrupt))
        .context("перехват SIGTERM")?;

    let runs_root = e2e_root.join("runs");
    warn_if_suspect(&runs_root);

    let driver = driver::build(&profile, &stand, &repo_root(), Arc::clone(&interrupt))?;
    if args.recreate {
        driver.recreate().context("пересоздание окружения")?;
    }

    let deliveries = plan_deliveries(&profile, &stand, &vars);

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

/// Что раннер везёт в окружение перед первым действием подготовки.
///
/// Цели берутся из тех же переменных, которые видит кейс: разъедься доставка
/// с подстановкой, кейс искал бы пакет и фикстуры не там, куда их положили.
fn plan_deliveries(profile: &Profile, stand: &StandConfig, vars: &Vars) -> Vec<Delivery> {
    vec![
        Delivery::new(
            "пакет",
            stand.package.deb.clone(),
            vars.plain("package").unwrap_or(REMOTE_PACKAGE).to_owned(),
        ),
        Delivery::new(
            "фикстуры",
            profile.fixtures_source_path(&repo_root()),
            vars.plain("fixtures").unwrap_or(REMOTE_FIXTURES).to_owned(),
        ),
    ]
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

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
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

    #[test]
    fn deliveries_default_to_the_runner_layout() {
        let mut vars = Vars::new();
        vars.insert_plain("fixtures", REMOTE_FIXTURES);
        vars.insert_plain("package", REMOTE_PACKAGE);

        let deliveries = plan_deliveries(&profile(), &stand(), &vars);
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
        assert_eq!(deliveries[1].remote, REMOTE_FIXTURES);
    }

    #[test]
    fn a_stand_that_moves_the_fixtures_moves_the_delivery_with_them() {
        // Кейс подставляет {{fixtures}}; вези раннер каталог по своему адресу,
        // кейс искал бы фикстуры не там, где они лежат.
        let mut vars = Vars::new();
        vars.insert_plain("fixtures", "/srv/e2e/fixtures");

        let deliveries = plan_deliveries(&profile(), &stand(), &vars);
        assert_eq!(deliveries[1].remote, "/srv/e2e/fixtures");
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
