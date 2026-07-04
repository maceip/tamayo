// end-to-end verification of docs/index.html against the intended design:
//   idle egg intro -> zoomed 27-state movie in 6 chapters
//   NEXT/BACK step states (interrupting animations); scroll = button presses
//   gen-1 icon bands (4 top / 4 bottom: 6 chapters + egg home + book repo)
const puppeteer = require("puppeteer-core");

let pass = 0, fail = 0;
function check(name, ok, extra = "") {
  if (ok) { pass++; console.log(`PASS  ${name}`); }
  else    { fail++; console.log(`FAIL  ${name} ${extra}`); }
}
const sleep = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  const browser = await puppeteer.launch({
    executablePath: "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
    headless: "new",
    args: ["--hide-scrollbars"],
  });
  const page = await browser.newPage();
  await page.setViewport({ width: 900, height: 860 });
  const errors = [];
  page.on("console", m => { if (m.type() === "error") errors.push(m.text()); });
  page.on("pageerror", e => errors.push(e.message));
  await page.goto("file://" + require("path").resolve(__dirname, "../../docs/index.html"), { waitUntil: "networkidle0" });
  await sleep(700);

  const vh = 860, s1 = 0.9 * vh;
  const state = () => page.evaluate(() => ({
    mode, cur,
    zoomed: document.body.classList.contains("zoomed"),
    labels: [lblA.textContent, lblB.textContent, lblC.textContent],
    ctlVisible: getComputedStyle(document.getElementById("zoomctl")).opacity,
    texts: [...document.querySelectorAll("#lcd text")].map(t => t.textContent).join("|"),
    eggDots: document.querySelectorAll("circle.egg").length,
    icons: document.querySelectorAll("#lcd > g:nth-of-type(3) > g").length,
    rigT: document.querySelector(".rig").style.transform,
  }));

  // --- boot: idle egg, clipped at the fold ------------------------
  let s = await state();
  check("boot: idle mode", s.mode === "idle");
  check("boot: labels START/START/REPO", s.labels.join() === "START,START,REPO", s.labels.join());
  check("boot: 3d egg drawn", s.eggDots > 100, `dots=${s.eggDots}`);
  check("boot: 8 icon slots drawn", s.icons === 8, `icons=${s.icons}`);
  const y1 = await page.evaluate(() => document.querySelector(".rig").getBoundingClientRect().top);
  check("boot: egg pushed to the fold", y1 > vh * 0.4, `rigTop=${y1}`);
  const d1 = await page.evaluate(() => document.querySelectorAll("circle.egg")[50].getAttribute("cx"));
  await sleep(300);
  const d2 = await page.evaluate(() => document.querySelectorAll("circle.egg")[50].getAttribute("cx"));
  check("boot: egg rotates while idle", d1 !== d2);

  // --- intro scroll parks the egg, wheel presses START -------------
  await page.evaluate(t => scrollTo(0, t), s1);
  await sleep(450);
  s = await state();
  check("park: still idle at the parked point", s.mode === "idle");
  const foot = await page.evaluate(() => getComputedStyle(document.querySelector("footer")).opacity);
  check("park: footer faded in", +foot > 0.9, foot);
  await page.evaluate(() => dispatchEvent(new WheelEvent("wheel", { deltaY: 60, cancelable: true })));
  await sleep(1400);   // hatch burst
  s = await state();
  check("wheel at park: starts the movie", s.mode === "story" && s.cur === 0);
  check("zoom: body zoomed + control bar shown", s.zoomed && +s.ctlVisible === 1);
  const scale = await page.evaluate(() =>
    document.querySelector(".screen").getBoundingClientRect().width / 248);
  check("zoom: screen ~fills the window", scale > 2, `scale=${scale.toFixed(2)}`);
  check("story: labels BACK/NEXT/HOME", /BACK/.test(s.labels[0]) && /NEXT/.test(s.labels[1]) && /HOME/.test(s.labels[2]), s.labels.join());
  check("state 0: title card", /WAIT — WHAT IS THIS\?/.test(s.texts));

  // --- NEXT/BACK stepping, including rapid interrupting clicks -----
  await page.click("#zbtnB");
  await sleep(250);
  s = await state();
  check("NEXT: advances to state 1", s.cur === 1);
  check("state 1: the pup scene", /this is the pup/.test(s.texts));
  await page.click("#zbtnB"); await page.click("#zbtnB"); await page.click("#zbtnB");
  await sleep(250);
  s = await state();
  check("rapid NEXT x3: interrupts and lands on 4", s.cur === 4);
  // the active slot is the one carrying the inverted 48px highlight tile
  // (every slot now contains ink rects — the pixel icons themselves)
  const hl = await page.evaluate(() =>
    [...document.querySelectorAll("#lcd > g:nth-of-type(3) > g")].findIndex(g =>
      [...g.querySelectorAll("rect")].some(r => r.getAttribute("width") === "48")));
  check("icons: chapter 1 (machine) highlighted", hl === 1, `hl=${hl}`);
  await page.click("#zbtnA");
  await sleep(250);
  s = await state();
  check("BACK: steps back to 3", s.cur === 3);

  // --- wheel + keyboard + screen taps all step --------------------
  await page.evaluate(() => dispatchEvent(new WheelEvent("wheel", { deltaY: 60, cancelable: true })));
  await sleep(220);
  s = await state();
  check("wheel down: NEXT", s.cur === 4);
  await page.evaluate(() => dispatchEvent(new WheelEvent("wheel", { deltaY: -60, cancelable: true })));
  await sleep(220);
  s = await state();
  check("wheel up: BACK", s.cur === 3);
  await page.keyboard.press("ArrowRight");
  await sleep(220);
  check("keyboard right: NEXT", (await state()).cur === 4);
  const scr = await page.evaluate(() => {
    const r = document.querySelector(".screen").getBoundingClientRect();
    return { l: r.left, t: r.top, w: r.width, h: r.height };
  });
  await page.mouse.click(scr.l + scr.w * 0.7, scr.t + scr.h * 0.55);
  await sleep(220);
  check("tap right of screen: NEXT", (await state()).cur === 5);
  await page.mouse.click(scr.l + scr.w * 0.15, scr.t + scr.h * 0.55);
  await sleep(220);
  check("tap left edge of screen: BACK", (await state()).cur === 4);

  // --- icon jump + wrap + repo tap ---------------------------------
  await page.evaluate(() => {
    document.querySelectorAll("#lcd > g:nth-of-type(3) > g")[3]
      .dispatchEvent(new MouseEvent("click", { bubbles: true }));
  });
  await sleep(250);
  s = await state();
  check("icon tap: jumps to the proof chapter", s.cur === 13, `cur=${s.cur}`);
  await page.evaluate(() => goto(26));
  await sleep(300);
  s = await state();
  check("state 26: pomfrit named", /THAT WAS POMFRIT/.test(s.texts));
  const repo = await page.evaluate(() => {
    let opened = null;
    const orig = window.open;
    window.open = u => { opened = u; return null; };
    document.querySelector("#lcd g[style*='cursor']").dispatchEvent(new MouseEvent("click", { bubbles: true }));
    window.open = orig;
    return { opened, mode, cur };
  });
  check("repo book: opens github in new tab", repo.opened === "https://github.com/maceip/tamayo", String(repo.opened));
  check("repo book: stays in the movie", repo.mode === "story" && repo.cur === 26);
  await page.click("#zbtnB");
  await sleep(250);
  check("NEXT at the end: wraps to start", (await state()).cur === 0);

  // --- press feedback on both button sets --------------------------
  const fb = await page.evaluate(async () => {
    dispatchEvent(new Event("pointerdown"));
    pressButton("B");
    const mid = {
      phys: document.getElementById("btnB").classList.contains("pressed"),
      ctl:  document.getElementById("zbtnB").classList.contains("pressed"),
      lit:  document.querySelector(".screen").classList.contains("lit"),
    };
    await new Promise(r => setTimeout(r, 300));
    return { ...mid, cleared: !document.getElementById("zbtnB").classList.contains("pressed"), audio: actx !== null };
  });
  check("press: both button sets dip", fb.phys && fb.ctl);
  check("press: screen glows and clears", fb.lit && fb.cleared);
  check("press: audio unlocked on first touch", fb.audio);

  // --- BACK at state 0 exits; HOME exits; scroll state sane ---------
  await page.click("#zbtnA");   // BACK at 0 -> exit
  await sleep(1100);
  s = await state();
  check("BACK at state 0: exits to idle egg", s.mode === "idle" && !s.zoomed && s.eggDots > 100);
  const sy = await page.evaluate(() => scrollY);
  check("exit: page still parked at egg-center", Math.abs(sy - s1) < 40, `scrollY=${sy}`);
  await page.evaluate(() => dispatchEvent(new WheelEvent("wheel", { deltaY: 60, cancelable: true })));
  await sleep(1300);
  check("wheel again: movie restarts", (await state()).mode === "story");
  await page.click("#zbtnC");   // HOME
  await sleep(1100);
  s = await state();
  check("HOME: exits to idle egg", s.mode === "idle" && !s.zoomed);

  check("no console/page errors", errors.length === 0, errors.join("; "));

  console.log(`\n${pass} passed, ${fail} failed`);
  await browser.close();
  process.exit(fail ? 1 : 0);
})();
