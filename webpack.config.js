module.exports = [
  {
    target: "webworker",
    context: __dirname,
    entry: "./cloudflare_worker.js",
    mode: "development",
    devtool: 'cheap-module-source-map',
  },
  {
    target: "webworker",
    entry:"./cloudflare_worker.js",
    mode:"production"
  }
];