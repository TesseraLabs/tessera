// Срезы графа для `spec.mjs context` и `spec.mjs why`. Обход идёт по типам
// рёбер из profile.yaml (`slices.*.follow`), а не по глубине — см. constitution.md
// и profile.yaml. При исчерпании бюджета узлы деградируют до имён, а не
// обрезаются молча (profile.yaml → budget.on_exhaustion).

import { buildGraph, resolveLink, computeObligations } from './graph.mjs';

/**
 * Находит узел графа (сущность или норма) по id — O(1) через индекс
 * {@link import('./graph.mjs').buildGraph}`.nodesById`, а не линейный
 * `nodes.find(...)` на каждый вызов (REVIEW.md M9): вызывается внутри
 * поэрёберного цикла обхода, `nodes.find` там был бы O(E·N).
 * @param {{nodesById: Map<string, import('./graph.mjs').GraphNode>}} graph
 * @param {string} id
 * @returns {import('./graph.mjs').GraphNode|undefined}
 */
function findNode(graph, id) {
  return graph.nodesById.get(id);
}

/**
 * Находит файл требования (норма) — файл, в котором объявлен заголовок с этим
 * ID. O(1) через `repo.requirementsById`, построенный один раз в `loadRepo`
 * (REVIEW.md M9) — раньше сканировал repo.files × file.requirements на каждый
 * вызов, а `crossContextAllowed` дёргает его на КАЖДОЕ ребро обхода.
 * @param {import('./graph.mjs').Repo} repo
 * @param {string} reqId
 * @returns {{file: import('./parse.mjs').SpecFile, req: import('./parse.mjs').Requirement}|null}
 */
function findRequirement(repo, reqId) {
  return repo.requirementsById.get(reqId) || null;
}

/**
 * Находит первый непустой абзац после заголовка `# Title` (используется для
 * `load: heading` — заголовок и первый абзац файла-решения/паттерна).
 * @param {import('./parse.mjs').SpecFile} file
 * @returns {string}
 */
function firstParagraph(file) {
  const lines = file.bodyLines;
  let i = 0;
  // пропустить первый заголовок `# ...`
  while (i < lines.length && !/^#\s+/.test(lines[i])) i++;
  i++;
  while (i < lines.length && lines[i].trim() === '') i++;
  const para = [];
  while (i < lines.length && lines[i].trim() !== '' && !/^#{1,6}\s+/.test(lines[i])) {
    para.push(lines[i]);
    i++;
  }
  return para.join(' ').trim();
}

/**
 * Обёртка вокруг budget.max_files: считает только уникальные полные загрузки
 * ФАЙЛОВ — как и объявлено в profile.yaml ("При исчерпании бюджета обход НЕ
 * обрезается молча"). Ключ обязан быть путём файла, а не `путь#id-требования`
 * (REVIEW.md M7): раньше двадцать шесть требований ОДНОГО markdown-файла
 * исчерпывали `max_files: 25`, загрузив на самом деле один файл.
 */
class Budget {
  /** @param {number} maxFiles */
  constructor(maxFiles) {
    this.maxFiles = maxFiles;
    this.loaded = new Set();
  }

  /** @param {string} key */
  tryLoad(key) {
    if (this.loaded.has(key)) return true;
    if (this.loaded.size >= this.maxFiles) return false;
    this.loaded.add(key);
    return true;
  }
}

/**
 * Проверяет допустимость перехода через границу контекста согласно cross_context
 * среза: `contract_only` пропускает только требования kind=контракт, `open` — всё.
 * @param {import('./graph.mjs').GraphNode} node
 * @param {string|undefined} sourceContext
 * @param {'contract_only'|'open'|undefined} policy
 * @param {import('./graph.mjs').Repo} repo
 * @returns {boolean}
 */
function crossContextAllowed(node, sourceContext, policy, repo) {
  if (!node.context || node.context === sourceContext) return true;
  if (policy === 'open') return true;
  if (policy !== 'contract_only') return false;
  if (node.kind !== 'норма') return false;
  const found = findRequirement(repo, node.id);
  return !!found && found.req.kindAttr === 'контракт';
}

/**
 * Рендерит узел графа согласно режиму загрузки (`full`/`names`/`heading`).
 * @param {import('./graph.mjs').GraphNode} node
 * @param {'full'|'names'|'heading'} load
 * @param {import('./graph.mjs').Repo} repo
 * @param {Budget} budget
 * @param {string[]} deferred
 * @returns {string|null}
 */
function renderNode(node, load, repo, budget, deferred) {
  if (load === 'names') {
    return `- ${node.id} (${node.kind}, ${node.path}) — ${node.name}`;
  }
  if (load === 'heading') {
    const file = repo.filesByPath.get(node.path);
    if (!file) return `- ${node.id} — ${node.name}`;
    return `## ${node.kind}: ${node.name}\n\n${firstParagraph(file)}`;
  }
  // load === 'full'
  if (node.kind === 'норма') {
    const found = findRequirement(repo, node.id);
    if (!found) return null;
    // Ключ бюджета — путь ФАЙЛА, не `путь#id-требования` (REVIEW.md M7): норма
    // расходует бюджет как часть загрузки своего файла, не как отдельный слот.
    if (!budget.tryLoad(found.file.path)) {
      deferred.push(node.id);
      return null;
    }
    const { file, req } = found;
    const text = file.bodyLines.slice(req.headingLine - file.bodyStartLine, req.sectionEnd - file.bodyStartLine).join('\n');
    return `--- ${file.path} (${node.id}) ---\n${text}`;
  }
  const file = repo.filesByPath.get(node.path);
  if (!file) return null;
  if (!budget.tryLoad(file.path)) {
    deferred.push(node.id);
    return null;
  }
  return `--- ${file.path} ---\n${file.raw}`;
}

/**
 * Рендерит вычисленные обязательства применённого паттерна (не страницу
 * паттерна — конституция §6).
 * @param {import('./graph.mjs').Entity} entity
 * @param {import('./graph.mjs').Repo} repo
 * @returns {string}
 */
function renderObligations(entity, repo) {
  const obligations = computeObligations(entity, repo);
  if (obligations.length === 0) return '';
  const lines = [`## Обязательства применённых паттернов термина ${entity.id}`];
  for (const ob of obligations) {
    const evidence = ob.hasEvidence
      ? ob.evidenceAnchors.map((a) => `${a.type}:${a.target}`).join(', ')
      : 'evidence ОТСУТСТВУЕТ';
    lines.push(`- ${ob.id} (kind=${ob.kindAttr ?? '?'}): ${evidence}`);
  }
  return lines.join('\n');
}

/**
 * Рендерит evidence-ребро (якорь кода/теста/схемы) — полный список типизированных якорей.
 * @param {import('./graph.mjs').GraphEdge} edge
 * @returns {string}
 */
function renderEvidence(edge) {
  return `- evidence: ${edge.anchorType}:${edge.to}`;
}

/**
 * @param {import('./graph.mjs').Repo} repo
 * @param {ReturnType<typeof buildGraph>} graph
 * @param {string} seedId
 * @param {Record<string,*>} sliceDef
 * @returns {{ text: string, deferred: string[] }}
 */
function runNamedSlice(repo, graph, seedId, sliceDef) {
  const budget = new Budget((repo.profile.budget && repo.profile.budget.max_files) || Infinity);
  const deferred = [];
  const blocks = [];
  // Дедупликация отрисовки узла (REVIEW.md M8): без неё цикл в графе (термин
  // упомянут и в прозе — ребро "ссылка", и как субъект нормы — ребро "субъект")
  // либо два параллельных ребра разных типов между одной парой узлов выводят
  // ОДИН И ТОТ ЖЕ узел дважды — и это происходит В ОБХОД бюджета, потому что
  // `Budget.tryLoad` для уже загруженного ключа просто возвращает true. Ключ —
  // id узла и режим загрузки: `full` и `names` одного узла — разный текст,
  // оба легитимны, если оба реально запрошены разными шагами среза.
  const renderedNodes = new Set();
  const renderedObligations = new Set();
  function renderOnce(node, load, deferredList) {
    const key = `${node.id} ${load}`;
    if (renderedNodes.has(key)) return null;
    renderedNodes.add(key);
    return renderNode(node, load, repo, budget, deferredList);
  }

  let seedNode = findNode(graph, seedId);
  if (!seedNode) {
    // Возможно, дан символ кода (seed "символ" в срезе why) — синтетический узел.
    seedNode = { id: seedId, kind: 'символ', context: undefined, path: '', name: seedId };
  }
  // Seed НЕ списывает бюджет (REVIEW.md M7): его собственный текст никогда не
  // попадает в `blocks` — только результаты обхода ОТ него. Раньше seed
  // резервировал единицу бюджета до того, как хоть что-то отрисовано, и при
  // `max_files: 1` срез не выдавал вообще ничего содержательного.

  // Каждый шаг `follow` в profile.yaml — самостоятельный обход ОТ SEED, а не
  // продолжение предыдущего шага: "решение", "evidence" и "обратные" всегда
  // читают ссылки самого seed-узла. Исключение — "применённый-паттерн", который
  // осмысленно продолжает цепочку "субъект" (обязательства несёт СУБЪЕКТ нормы,
  // а не сама норма).
  const seedFrontier = [seedNode];
  let subjectFrontier = seedFrontier;

  for (const step of sliceDef.follow || []) {
    const origin = step.edge === 'применённый-паттерн' ? subjectFrontier : seedFrontier;

    if (step.edge === 'обратные') {
      let currentIds = new Set(origin.map((n) => n.id));
      let hopsLeft = step.hops || 1;
      const seenEdges = new Set();
      while (hopsLeft > 0 && currentIds.size > 0) {
        const incoming = graph.edges.filter((e) => currentIds.has(e.to));
        const newFrom = new Set();
        for (const e of incoming) {
          const key = `${e.from}>${e.to}:${e.type}`;
          if (seenEdges.has(key)) continue;
          seenEdges.add(key);
          const fromNode = findNode(graph, e.from);
          if (!fromNode) continue;
          if (!crossContextAllowed(fromNode, seedNode.context, sliceDef.cross_context, repo)) continue;
          const rendered = renderOnce(fromNode, step.load, deferred);
          if (rendered) blocks.push(rendered);
          newFrom.add(fromNode.id);
        }
        currentIds = newFrom;
        hopsLeft--;
      }
      continue;
    }

    const relevant = graph.edges.filter((e) => origin.some((n) => n.id === e.from) && e.type === step.edge);
    const stepTargets = [];
    for (const e of relevant) {
      if (step.edge === 'evidence') {
        blocks.push(renderEvidence(e));
        continue;
      }
      if (step.edge === 'применённый-паттерн') {
        const fromEntity = repo.entities.find((en) => en.id === e.from);
        if (!fromEntity) continue;
        // One entity has one computed obligation bundle even when it applies
        // several patterns. The graph has one edge per pattern, so rendering
        // the whole bundle for every edge duplicated it N times.
        if (renderedObligations.has(fromEntity.id)) continue;
        renderedObligations.add(fromEntity.id);
        const rendered = renderObligations(fromEntity, repo);
        if (rendered) blocks.push(rendered);
        continue;
      }
      const targetNode = findNode(graph, e.to);
      if (!targetNode) continue;
      if (!crossContextAllowed(targetNode, seedNode.context, sliceDef.cross_context, repo)) continue;
      const rendered = renderOnce(targetNode, step.load, deferred);
      if (rendered) blocks.push(rendered);
      stepTargets.push(targetNode);
    }
    if (step.edge === 'субъект' && stepTargets.length > 0) subjectFrontier = stepTargets;
  }

  // Дубликаты в `deferred` схлопываются (REVIEW.md M7 — тот же id мог быть
  // отложен несколькими рёбрами до дедупликации выше), а формат совпадает с
  // `renderNode(..., 'names', ...)`, а не с голым id.
  const uniqueDeferred = [...new Set(deferred)];
  const onExhaustion = (repo.profile.budget && repo.profile.budget.on_exhaustion) || 'degrade_to_names';
  if (uniqueDeferred.length > 0 && onExhaustion === 'error') {
    const names = uniqueDeferred.map((id) => {
      const n = findNode(graph, id);
      return n ? `${n.id} (${n.kind}, ${n.path})` : id;
    });
    throw new Error(`бюджет исчерпан (budget.max_files=${budget.maxFiles}), on_exhaustion="error": не отрисовано ${uniqueDeferred.length} узлов: ${names.join(', ')}`);
  }

  let text = blocks.filter(Boolean).join('\n\n');
  if (uniqueDeferred.length > 0) {
    text += `\n\n--- за границей бюджета (budget.max_files=${budget.maxFiles}), деградировано до имён ---\n`;
    text += uniqueDeferred
      .map((id) => {
        const n = findNode(graph, id);
        return n ? `- ${n.id} (${n.kind}, ${n.path}) — ${n.name}` : `- ${id}`;
      })
      .join('\n');
  }
  return { text, deferred: uniqueDeferred };
}

/**
 * `spec.mjs context <id> --slice <implement|why|review>`.
 * @param {import('./graph.mjs').Repo} repo
 * @param {string} seedId
 * @param {string} sliceName
 * @returns {string}
 */
export function contextSlice(repo, seedId, sliceName) {
  const sliceDef = repo.profile.slices && repo.profile.slices[sliceName];
  if (!sliceDef) {
    throw new Error(`неизвестный срез "${sliceName}" — доступны: ${Object.keys(repo.profile.slices || {}).join(', ')}`);
  }
  const graph = buildGraph(repo);
  if (!findNode(graph, seedId) && !findRequirement(repo, seedId)) {
    throw new Error(`узел "${seedId}" не найден в графе`);
  }
  const { text } = runNamedSlice(repo, graph, seedId, sliceDef);
  return text || `(срез "${sliceName}" для "${seedId}" пуст)`;
}

/**
 * `spec.mjs context --slice review --seed-files <файл>` /
 * `--seed-git <ref>` — засев среза "review" списком ИЗМЕНЁННЫХ файлов
 * (profile.yaml: `slices.review.seed: [изменённые-файлы]`). Раньше этого
 * засева не было НИКАК — срез "review" не запускался вообще, хотя это ровно
 * сценарий "какие нормы задело изменение", ради которого он заведён
 * (REVIEW.md P2, задание второй фазы п.3).
 *
 * Каждый путь резолвится в один или несколько seed-узлов графа: если путь
 * совпадает со спек-файлом — его собственный термин; если это файл продукта —
 * все узлы, у которых есть evidence-ребро НА этот файл (тот же критерий,
 * что у {@link why}: любой code:/exemplar:/counterexample:/type:-якорь на
 * файл целиком, независимо от символа). Путь, не резолвящийся ни в то, ни
 * в другое, тихо пропускается — это нормально для файлов вне зоны spec2
 * (стили, конфиги), а не ошибка.
 * @param {import('./graph.mjs').Repo} repo
 * @param {string[]} seedFilePaths пути относительно корня продукта (как из `git diff --name-only`)
 * @returns {string}
 */
export function reviewSlice(repo, seedFilePaths) {
  const sliceDef = repo.profile.slices && repo.profile.slices.review;
  if (!sliceDef) {
    throw new Error('срез "review" не объявлен в profile.yaml — слот slices.review.seed пуст');
  }
  const graph = buildGraph(repo);

  const seedIds = new Set();
  for (const rawPath of seedFilePaths) {
    const norm = String(rawPath).trim().replace(/\\/g, '/');
    if (norm === '') continue;
    // Спек-файл: путь совпадает с SpecFile.path (относительно корня spec2/) —
    // либо напрямую, либо как хвост после "spec2/".
    const specFile = repo.filesByPath.get(norm) || repo.filesByPath.get(norm.replace(/^spec2\//, ''));
    if (specFile && specFile.frontmatter && specFile.frontmatter.id) {
      seedIds.add(specFile.frontmatter.id);
      continue;
    }
    // Файл продукта: узлы с evidence-ребром на этот путь — тот же критерий,
    // что у `why()`.
    for (const e of graph.edges) {
      if (e.type !== 'evidence') continue;
      const edgeFile = e.to.split('#')[0];
      if (edgeFile === norm) seedIds.add(e.from);
    }
  }

  if (seedIds.size === 0) {
    return `(срез "review" пуст: ни один из ${seedFilePaths.length} изменённых файлов не резолвится ни в спек-файл, ни в evidence-якорь)`;
  }

  // Несколько seed-узлов дают дублирующиеся куски текста (общий сосед, общее
  // требование) — блоки дедуплицируются по итоговому тексту, не по seed'у.
  const seenBlocks = new Set();
  const sections = [];
  for (const seedId of [...seedIds].sort()) {
    const { text } = runNamedSlice(repo, graph, seedId, sliceDef);
    if (!text || seenBlocks.has(text)) continue;
    seenBlocks.add(text);
    sections.push(`=== засев: ${seedId} ===\n${text}`);
  }
  return sections.length > 0
    ? sections.join('\n\n')
    : `(срез "review" для ${seedIds.size} засеянных узлов пуст)`;
}

/**
 * `spec.mjs why <path>[#symbol]` — обратный индекс: по файлу или символу кода
 * находит нормы, которые ссылаются на него через evidence-якорь `code:`, их
 * термины и связанные решения.
 * @param {import('./graph.mjs').Repo} repo
 * @param {string} target путь или `путь#символ`
 * @returns {string}
 */
export function why(repo, target) {
  const hashIdx = target.indexOf('#');
  const filePart = hashIdx === -1 ? target : target.slice(0, hashIdx);
  const symbolPart = hashIdx === -1 ? null : target.slice(hashIdx + 1);

  const graph = buildGraph(repo);
  const matchingEdges = graph.edges.filter((e) => {
    if (e.type !== 'evidence') return false;
    if (e.anchorType !== 'code' && e.anchorType !== 'exemplar' && e.anchorType !== 'counterexample' && e.anchorType !== 'type') return false;
    const [edgeFile, edgeSymbol] = e.to.split('#');
    if (edgeFile !== filePart) return false;
    if (symbolPart && edgeSymbol !== symbolPart) return false;
    return true;
  });

  if (matchingEdges.length === 0) return `(ничего не ссылается на "${target}" через code:-якорь)`;

  const lines = [];
  for (const e of matchingEdges) {
    const fromNode = findNode(graph, e.from);
    const label = fromNode ? `${fromNode.id} (${fromNode.kind}, ${fromNode.path})` : e.from;
    lines.push(`## ${label} — evidence: ${e.anchorType}:${e.to}`);

    // Термин, которому принадлежит норма (если from — сама норма).
    const reqInfo = findRequirement(repo, e.from);
    const owningFile = reqInfo ? reqInfo.file : repo.files.find((f) => f.path === fromNode?.path);
    if (owningFile && owningFile.frontmatter) {
      lines.push(`  термин: ${owningFile.frontmatter.id} (${owningFile.frontmatter.kind}, ${owningFile.path})`);
    }

    // Связанные решения: рёбра "решение" от той же нормы/термина.
    const decisionEdges = graph.edges.filter((d) => d.from === e.from && d.type === 'решение');
    for (const d of decisionEdges) {
      const decisionNode = findNode(graph, d.to);
      lines.push(`  решение: ${decisionNode ? `${decisionNode.id} — ${decisionNode.name}` : d.to}`);
    }
  }
  return lines.join('\n');
}
