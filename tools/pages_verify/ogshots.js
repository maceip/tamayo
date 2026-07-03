// renders the real page and captures the egg for og:image + favicon
const puppeteer = require("puppeteer-core");

(async () => {
  const browser = await puppeteer.launch({
    executablePath: "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
    headless: "new",
    args: ["--hide-scrollbars"],
  });
  const page = await browser.newPage();
  await page.setViewport({ width: 1200, height: 900, deviceScaleFactor: 2 });
  await page.goto("file://" + require("path").resolve(__dirname, "../../docs/index.html"), { waitUntil: "networkidle0" });
  // center the egg (end of the intro zone) and drop overlay chrome
  await page.evaluate(() => {
    scrollTo(0, 0.9 * innerHeight - 2);
    document.querySelector(".scroll-hint").style.display = "none";
    document.querySelector("footer").style.display = "none";
  });
  await new Promise(r => setTimeout(r, 900));

  // clip is in document coordinates: add the scroll offset to the rect
  const egg = await page.evaluate(() => {
    const r = document.querySelector(".egg-shell").getBoundingClientRect();
    return { x: r.x + scrollX, y: r.y + scrollY, w: r.width, h: r.height };
  });
  const cx = egg.x + egg.w / 2, cy = egg.y + egg.h / 2;

  // og: 1200x630 crop centered on the egg (page background fills the rest)
  await page.screenshot({
    path: "/tmp/og_raw.png",
    clip: { x: 0, y: Math.max(0, cy - 315), width: 1200, height: 630 },
  });

  // icon: square crop around the egg, a hair wider than the shell
  const side = egg.h * 1.12;
  await page.screenshot({
    path: "/tmp/icon_raw.png",
    clip: { x: cx - side / 2, y: cy - side / 2, width: side, height: side },
  });

  await browser.close();
  console.log("captured", JSON.stringify(egg));
})();
