{ pkgs ? import <nixpkgs> {},
  python ? pkgs.python3Packages }:

python.buildPythonPackage {
  pname = "intrustd-support";
  version = "0.1.0";

  src = ./.;

  buildInputs = with python; [ requests ];
  nativeBuildInputs = with python; [ pytest ];

  meta = {
    license = pkgs.stdenv.lib.licenses.mit;
    homepage = "https://intrustd.com/";
  };
}
