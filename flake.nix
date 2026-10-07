{
  description = "Snake as an ARMIS client applet for Estonian ID cards";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  # ext/armis-applet-ecosystem (with its SDK and GP export submodules) is part of the build
  inputs.self.submodules = true;

  outputs = { self, nixpkgs }:
    let
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
      jdk = pkgs.jdk11; # JC 3.0.4 converter caps at JDK 11
      tools = {
        ant-javacard = pkgs.fetchurl {
          url = "https://github.com/martinpaljak/ant-javacard/releases/download/v26.05.15/ant-javacard.jar";
          hash = "sha256-FPXiXAexhOTsAu4UiJLC6nrV1+nbi5EQlSTfj30ABYk=";
        };
        jcardsim = pkgs.fetchurl {
          url = "https://repo1.maven.org/maven2/com/klinec/jcardsim/3.0.6.0/jcardsim-3.0.6.0.jar";
          hash = "sha256-223n/95xZRxF0A334WB3FoXOw+FOREvza3lmWNKJlC8=";
        };
      };
      antFlags = "-Dant-javacard.jar=${tools.ant-javacard} -Djcardsim.jar=${tools.jcardsim}";
    in {
      packages.x86_64-linux.default = pkgs.stdenvNoCC.mkDerivation {
        pname = "armis-snake";
        version = "1.0";
        src = self;
        nativeBuildInputs = [ jdk pkgs.ant ];
        JAVA_HOME = jdk.home;
        buildPhase = "ant ${antFlags} cap";
        doCheck = true;
        checkPhase = "ant ${antFlags} test";
        installPhase = ''
          install -Dm644 build/armis-snake.cap $out/armis-snake.cap
          (cd $out && sha256sum armis-snake.cap > SHA256SUMS)
        '';
      };

      devShells.x86_64-linux.default = pkgs.mkShell {
        packages = [ jdk pkgs.ant ];
        JAVA_HOME = jdk.home;
      };
    };
}
