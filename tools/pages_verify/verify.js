// End-to-end verification for docs/index.html (the delegation-story explainer).
const fs = require("fs");
const path = require("path");
const puppeteer = require("puppeteer-core");

let pass = 0, fail = 0;
function check(name, ok, extra = "") {
  if (ok) { pass++; console.log(`PASS  ${name}`); }
  else { fail++; console.log(`FAIL  ${name} ${extra}`); }
}
const sleep = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  const root = path.resolve(__dirname, "../..");
  const indexPath = path.join(root, "docs/index.html");
  const html = fs.readFileSync(indexPath, "utf8");

  check("public index does not link the retired tamagotchi movie", !/tamagotchi\.html/i.test(html));
  check("public index does not load old d3 movie dependency", !/d3@7|cdn\.jsdelivr\.net\/npm\/d3/i.test(html));
  check("public index contains delegated software story", /Let the agent through/.test(html));

  const browser = await puppeteer.launch({
    executablePath: "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
    headless: "new",
    args: ["--hide-scrollbars"],
  });

  for (const viewport of [{ width: 1280, height: 900 }, { width: 390, height: 844 }]) {
    const page = await browser.newPage();
    const errors = [];
    page.on("console", m => { if (m.type() === "error") errors.push(m.text()); });
    page.on("pageerror", e => errors.push(e.message));
    await page.setViewport(viewport);
    await page.goto("file://" + indexPath, { waitUntil: "networkidle0" });
    await sleep(400);

    const boot = await page.evaluate(() => ({
      title: document.querySelector("h1")?.textContent || "",
      scene: window.__tamayoSiteState?.scene,
      token: window.__tamayoSiteState?.token,
      oldRefs: [...document.querySelectorAll("a, script, iframe")].some(el =>
        /tamagotchi\.html/i.test(el.getAttribute("href") || el.getAttribute("src") || "")),
      overflow: document.documentElement.scrollWidth > window.innerWidth + 1,
    }));
    check(`${viewport.width}: hero renders`, /agent through/.test(boot.title), boot.title);
    check(`${viewport.width}: first story scene active`, boot.scene === "normal-task", boot.scene);
    check(`${viewport.width}: first token active`, boot.token === "Burn token", boot.token);
    check(`${viewport.width}: no runtime old-page refs`, !boot.oldRefs);
    check(`${viewport.width}: no horizontal overflow`, !boot.overflow);

    await page.click("#nextStep");
    await sleep(120);
    const next = await page.evaluate(() => window.__tamayoSiteState);
    check(`${viewport.width}: next advances story`, next.stepIndex === 1 && next.scene === "device-cloud", JSON.stringify(next));

    await page.click("#prevStep");
    await sleep(120);
    const prev = await page.evaluate(() => window.__tamayoSiteState);
    check(`${viewport.width}: previous returns story`, prev.stepIndex === 0 && prev.scene === "normal-task", JSON.stringify(prev));

    await page.evaluate(() => document.querySelector("#passes").scrollIntoView());
    await sleep(120);
    await page.click(".token-button:nth-child(3)");
    await sleep(120);
    const token = await page.evaluate(() => ({
      state: window.__tamayoSiteState,
      learns: document.querySelector("#tokenLearns")?.textContent,
      hidden: document.querySelector("#tokenHidden")?.textContent,
    }));
    check(`${viewport.width}: token catalogue switches`, token.state.token === "Policy-bound email token", JSON.stringify(token));
    check(`${viewport.width}: email token detail shown`, /email/i.test(token.learns), token.learns);

    check(`${viewport.width}: no console/page errors`, errors.length === 0, errors.join(" | "));
    await page.close();
  }

  await browser.close();
  console.log(`\n${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
})();
