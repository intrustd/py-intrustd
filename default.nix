{ pkgs ? import <nixpkgs> {},
  python3 ? pkgs.python3 }:

python3.pkgs.buildPythonPackage {
  pname = "intrustd-support";
  version = "0.1.0";

  src = ./.;

  propagatedBuildInputs = with python3.pkgs; [ requests ];
  propagatedNativeBuildInputs = with python3.pkgs; [ pytest ];

  meta = {
    license = pkgs.stdenv.lib.licenses.mit;
    homepage = "https://intrustd.com/";
  };
}
