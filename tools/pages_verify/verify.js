// end-to-end verification of docs/index.html against the intended design:
//   zones: egg slide-in -> menu -> auto-picked, auto-playing, looping story
//   gen-1 buttons: A cycles, B picks, C cancels; labels follow the mode
//   press feedback: .pressed class, screen glow, audio unlock hook
const puppeteer = require("puppeteer-core");

let pass = 0, fail = 0;
function check(name, ok, extra = "") {
  if (ok) { pass++; console.log(`PASS  ${name}`); }
  else    { fail++; console.log(`FAIL  ${name} ${extra}`); }
}

(async () => {
  const browser = await puppeteer.launch({
    executablePath: "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
    headless: "new",
    args: ["--hide-scrollbars"],
  });
  const page = await browser.newPage();
  await page.setViewport({ width: 760, height: 860 });
  const errors = [];
  page.on("console", m => { if (m.type() === "error") errors.push(m.text()); });
  page.on("pageerror", e => errors.push(e.message));
  await page.goto("file://" + require("path").resolve(__dirname, "../../docs/index.html"), { waitUntil: "networkidle0" });
  await new Promise(r => setTimeout(r, 700));

  const vh = 860, s1 = 0.9 * vh, s2 = s1 + 0.7 * vh;
  const state = () => page.evaluate(() => ({
    mode, zone: lastZone, sel: menuSel,
    labels: [lblA.textContent, lblB.textContent, lblC.textContent],
    captions: [...document.querySelectorAll("#lcd g:nth-of-type(3) text")].map(t => t.textContent),
    rigY: document.querySelector(".rig").getBoundingClientRect().top,
    eggDots: document.querySelectorAll("circle.egg").length,
    mathOp: +document.querySelectorAll("#lcd > g")[4].getAttribute("opacity"),
  }));

  // --- boot state -------------------------------------------------
  let s = await state();
  check("boot: idle mode", s.mode === "idle");
  check("boot: labels MENU/HATCH/MATH", s.labels.join() === "MENU,HATCH,MATH", s.labels.join());
  check("boot: 3d egg is drawn", s.eggDots > 100, `dots=${s.eggDots}`);
  const y1 = await page.evaluate(() => document.querySelector(".rig").getBoundingClientRect().top);
  check("boot: egg pushed to the fold (clipped)", y1 > vh * 0.4, `rigTop=${y1}`);
  const hintOp = await page.evaluate(() => getComputedStyle(document.querySelector(".scroll-hint")).opacity);
  check("boot: scroll hint visible", +hintOp === 1);

  // egg actually rotating: a mid-latitude dot moves over time (dot 0 is
  // the pole, which sits on the rotation axis and legitimately stays put)
  const d1 = await page.evaluate(() => document.querySelectorAll("circle.egg")[50].getAttribute("cx"));
  await new Promise(r => setTimeout(r, 300));
  const d2 = await page.evaluate(() => document.querySelectorAll("circle.egg")[50].getAttribute("cx"));
  check("boot: egg rotates while idle", d1 !== d2);

  // --- zone 1: menu ------------------------------------------------
  await page.evaluate(t => scrollTo(0, t), s1 + 80);
  await new Promise(r => setTimeout(r, 500));
  s = await state();
  check("menu: mode switches", s.mode === "menu");
  check("menu: labels NEXT/PICK/HOME", /NEXT/.test(s.labels[0]) && s.labels[1] === "PICK" && s.labels[2] === "HOME", s.labels.join());
  check("menu: demo highlighted first", s.sel === 0);
  check("menu: scroll-forward caption", s.captions.some(c => /keep scrolling/.test(c)), s.captions.join("|"));
  const menuTexts = await page.evaluate(() =>
    [...document.querySelectorAll("#lcd text")].map(t => t.textContent).join("|"));
  check("menu: big what-is-this text", /WAIT — WHAT IS THIS\?/.test(menuTexts));
  check("menu: three options listed", /SHOW ME THE DEMO/.test(menuTexts) && /SHOW ME THE MATH/.test(menuTexts) && /SHOW ME THE REPO/.test(menuTexts));

  // A cycles the highlight (gen-1 semantics)
  await page.click("#btnA");
  await new Promise(r => setTimeout(r, 250));
  s = await state();
  check("menu: A cycles highlight to math", s.sel === 1);
  await page.click("#btnA"); await page.click("#btnA");
  await new Promise(r => setTimeout(r, 250));
  s = await state();
  check("menu: A wraps back to demo", s.sel === 0);

  // press feedback machinery
  const fb = await page.evaluate(async () => {
    dispatchEvent(new Event("pointerdown"));         // unlock audio
    pressButton("B");
    const mid = {
      btn: document.getElementById("btnB").classList.contains("pressed"),
      lit: document.querySelector(".screen").classList.contains("lit"),
    };
    await new Promise(r => setTimeout(r, 320));
    return {
      ...mid,
      cleared: !document.getElementById("btnB").classList.contains("pressed"),
      audio: actx !== null,
      canVibrate: typeof navigator.vibrate,
    };
  });
  check("press: button dips (.pressed)", fb.btn);
  check("press: screen glows (.lit)", fb.lit);
  check("press: feedback clears", fb.cleared);
  check("press: audio context created on first touch", fb.audio);

  // repo pick opens a tab, never navigates the page
  const repo = await page.evaluate(() => {
    let opened = null;
    const orig = window.open;
    window.open = (u) => { opened = u; return null; };
    pick(2);
    window.open = orig;
    return { opened, mode };
  });
  check("menu: repo pick opens github in new tab", repo.opened === "https://github.com/maceip/tamayo", String(repo.opened));
  check("menu: repo pick stays on menu", repo.mode === "menu");

  // --- zone 2: auto-pick + the movie -------------------------------
  await page.evaluate(t => scrollTo(0, t), s2 + 60);
  await new Promise(r => setTimeout(r, 400));
  s = await state();
  check("story: scroll past menu auto-picks demo", s.mode === "story");
  check("story: labels HOME/REPLAY/MATH", s.labels[0] === "HOME" && s.labels[1] === "REPLAY", s.labels.join());
  check("story: demo pick leaves math off", s.mathOp === 0, `op=${s.mathOp}`);

  // the movie plays hands-off: captions change without any scrolling
  const seen = new Set();
  for (let i = 0; i < 30; i++) {
    const c = (await state()).captions.join("|");
    if (c) seen.add(c);
    await new Promise(r => setTimeout(r, 450));
  }
  check("story: keeps animating unattended (4+ scenes)", seen.size >= 4, `distinct=${seen.size}`);

  // loop: with shortened beats, an early caption must reappear
  const loops = await page.evaluate(async () => {
    BEATS.forEach(b => b.dur = 220);
    pick(0);                                  // restart with fast beats
    const seq = [];
    for (let i = 0; i < 60; i++) {
      const c = [...document.querySelectorAll("#lcd g:nth-of-type(3) text")].map(t => t.textContent).join("|");
      if (c && c !== seq[seq.length - 1]) seq.push(c);
      await new Promise(r => setTimeout(r, 110));
    }
    const first = seq.findIndex(c => /three friends/.test(c));
    const again = seq.slice(first + 1).findIndex(c => /three friends/.test(c));
    return { n: seq.length, wraps: first >= 0 && again >= 0 };
  });
  check("story: loops past the finale", loops.wraps, `scenes=${loops.n}`);

  // MATH toggle mid-story
  await page.click("#btnC");
  await new Promise(r => setTimeout(r, 450));
  s = await state();
  check("story: C toggles math overlay on", s.mathOp === 1, `op=${s.mathOp}`);
  check("story: math label shows check", /✓/.test(s.labels[2]), s.labels[2]);
  await page.click("#btnC");

  // --- back out: story -> menu -> idle ------------------------------
  await page.evaluate(t => scrollTo(0, t), s1 + 80);
  await new Promise(r => setTimeout(r, 500));
  s = await state();
  check("back: scroll up cancels movie to menu", s.mode === "menu");
  await page.evaluate(() => scrollTo(0, 0));
  await new Promise(r => setTimeout(r, 600));
  s = await state();
  check("back: scroll to top returns to idle egg", s.mode === "idle" && s.eggDots > 100);
  const y2 = await page.evaluate(() => document.querySelector(".rig").getBoundingClientRect().top);
  check("back: egg slides back to the fold", y2 > vh * 0.4, `rigTop=${y2}`);

  // HOME from the story parks at the centered egg
  await page.evaluate(t => scrollTo(0, t), s2 + 60);
  await new Promise(r => setTimeout(r, 500));
  await page.click("#btnA");                       // HOME
  await new Promise(r => setTimeout(r, 1600));     // smooth scroll
  s = await state();
  const sy = await page.evaluate(() => scrollY);
  check("home: button returns to idle", s.mode === "idle");
  check("home: parks just before the menu band", Math.abs(sy - s1) < 30, `scrollY=${sy}`);

  check("no console/page errors", errors.length === 0, errors.join("; "));

  console.log(`\n${pass} passed, ${fail} failed`);
  await browser.close();
  process.exit(fail ? 1 : 0);
})();
