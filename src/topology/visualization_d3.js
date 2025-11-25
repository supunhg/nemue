// D3.js visualization script for network topology
const width = window.innerWidth;
const height = window.innerHeight;

const svg = d3.select('#topology')
    .attr('width', width)
    .attr('height', height);

const simulation = d3.forceSimulation(nodesData)
    .force('link', d3.forceLink(linksData).id(d => d.id).distance(150))
    .force('charge', d3.forceManyBody().strength(-500))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collision', d3.forceCollide().radius(40));

const link = svg.append('g')
    .selectAll('line')
    .data(linksData)
    .enter().append('line')
    .attr('class', 'link');

const node = svg.append('g')
    .selectAll('circle')
    .data(nodesData)
    .enter().append('circle')
    .attr('class', 'node')
    .attr('r', d => d.importance * 5 + 15)
    .attr('fill', d => d.color)
    .call(d3.drag()
        .on('start', dragstarted)
        .on('drag', dragged)
        .on('end', dragended));

const label = svg.append('g')
    .selectAll('text')
    .data(nodesData)
    .enter().append('text')
    .attr('class', 'label')
    .text(d => d.label)
    .attr('dx', 20)
    .attr('dy', 5);

simulation.on('tick', () => {
    link
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y);
    
    node
        .attr('cx', d => d.x)
        .attr('cy', d => d.y);
    
    label
        .attr('x', d => d.x)
        .attr('y', d => d.y);
});

function dragstarted(event, d) {
    if (!event.active) simulation.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
}

function dragged(event, d) {
    d.fx = event.x;
    d.fy = event.y;
}

function dragended(event, d) {
    if (!event.active) simulation.alphaTarget(0);
    d.fx = null;
    d.fy = null;
}
