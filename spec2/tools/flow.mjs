import { buildGraph } from './graph.mjs';

/**
 * Строит причинный срез. Relation хранится на странице, которая ею владеет,
 * но направление причинности может быть обратным (`policy reacts_to event`):
 * его задаёт `relation_types.<name>.flow` в профиле.
 */
export function traceFlow(repo, seedId) {
  const graph = buildGraph(repo);
  if (!graph.nodesById.has(seedId)) throw new Error(`узел "${seedId}" не найден`);
  const causal = [];
  const seen = new Set();
  for (const edge of graph.edges) {
    if (!edge.type.startsWith('relation:')) continue;
    const relation = edge.type.slice('relation:'.length);
    const direction = repo.profile.relation_types?.[relation]?.flow;
    if (direction !== 'forward' && direction !== 'reverse') continue;
    const from = direction === 'forward' ? edge.from : edge.to;
    const to = direction === 'forward' ? edge.to : edge.from;
    const key = `${from}\0${relation}\0${to}`;
    if (seen.has(key)) continue;
    seen.add(key);
    causal.push({ from, to, relation });
  }

  const reachableNodes = new Set([seedId]);
  const reachableEdges = [];
  const queue = [seedId];
  while (queue.length) {
    const from = queue.shift();
    for (const edge of causal.filter((candidate) => candidate.from === from)) {
      reachableEdges.push(edge);
      if (reachableNodes.has(edge.to)) continue;
      reachableNodes.add(edge.to);
      queue.push(edge.to);
    }
  }
  return { seed: seedId, nodes: [...reachableNodes], edges: reachableEdges };
}

export function formatFlow(repo, seedId) {
  const flow = traceFlow(repo, seedId);
  if (!flow.edges.length) return `причинный срез от "${seedId}" пуст`;
  const lines = [`Причинный срез: ${seedId}`];
  const depth = new Map([[seedId, 0]]);
  for (const edge of flow.edges) {
    const currentDepth = depth.get(edge.from) ?? 0;
    if (!depth.has(edge.to)) depth.set(edge.to, currentDepth + 1);
    lines.push(`${'  '.repeat(currentDepth)}${edge.from} --${edge.relation}--> ${edge.to}`);
  }
  return lines.join('\n');
}
