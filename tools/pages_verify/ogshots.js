// Render the current public page and refresh docs/og.png.
const path = require("path");
const puppeteer = require("puppeteer-core");

(async () => {
  const root = path.resolve(__dirname, "../..");
  const browser = await puppeteer.launch({
    executablePath: "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
    headless: "new",
    args: ["--hide-scrollbars"],
  });
  const page = await browser.newPage();
  await page.setViewport({ width: 1200, height: 630, deviceScaleFactor: 2 });
  await page.goto("file://" + path.join(root, "docs/index.html"), { waitUntil: "networkidle0" });
  await new Promise(r => setTimeout(r, 600));
  await page.screenshot({
    path: path.join(root, "docs/og.png"),
    clip: { x: 0, y: 0, width: 1200, height: 630 },
  });
  await browser.close();
  console.log("captured docs/og.png");
})();
