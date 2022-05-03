async function main() {
  const myCrypto = require('/home/tikal/projects/pyodide/releases/pyodide-build-0.20.0/pyodide/palisade/crypto')

  const createCrypto = () => {
    return new myCrypto();
  }
  console.log("createCrypto")
  globalThis.createCrypto = createCrypto;

  const factory = require('/data1/duality/secureplus-cfw/web/js/lib/palisade_pke')
  const module = await factory()

  let pyodide_pkg = await import("/home/tikal/projects/pyodide/releases/pyodide-build-0.20.0/pyodide/pyodide.js");

  // let pyodide = await pyodide_pkg.loadPyodide({
  //   indexURL: "/home/tikal/projects/pyodide/releases/pyodide-build-0.20.0/pyodide",
  // });

  globalThis.pyodide = await loadPyodide();
  await pyodide.loadPackage(['micropip', 'numpy', 'pandas']);
  globalThis.palisade_pke = module;
  let namespace = pyodide.globals.get("dict")();
  console.log('start')
  return pyodide.runPython(`1+1`);

}
main().then(exitCode => console.log(exitCode));
