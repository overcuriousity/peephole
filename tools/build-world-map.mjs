// Generates assets/world.svg: one <path id="XX"> per country (ISO alpha-2),
// Natural Earth 1 projection, 960x500. Source: world-atlas countries-110m
// (Natural Earth, public domain). Run: cd tools && npm install && node build-world-map.mjs
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { geoNaturalEarth1, geoPath } from "d3-geo";
import { feature } from "topojson-client";
import countries from "i18n-iso-countries";

const require = createRequire(import.meta.url);
const topo = JSON.parse(readFileSync(require.resolve("world-atlas/countries-110m.json"), "utf8"));
const fc = feature(topo, topo.objects.countries);

const W = 960, H = 500;
const projection = geoNaturalEarth1().fitSize([W, H], { type: "Sphere" });
const path = geoPath(projection);

let out = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="World map">\n`;
out += `<path class="sphere" d="${path({ type: "Sphere" })}"/>\n`;
let n = 0, skipped = [];
for (const f of fc.features) {
  const numeric = String(f.id).padStart(3, "0");
  const alpha2 = countries.numericToAlpha2(numeric);
  if (!alpha2 || alpha2 === "AQ") { skipped.push(numeric); continue; }
  const d = path(f);
  if (!d) continue;
  out += `<path class="country" id="${alpha2}" d="${d.replace(/(\d)\.(\d)\d+/g, "$1.$2")}"/>\n`;
  n++;
}
out += `</svg>\n`;
writeFileSync(new URL("../assets/world.svg", import.meta.url), out);
console.log(`wrote ${n} countries, skipped ${skipped.length}: ${skipped.join(",")}`);
