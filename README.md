# pwn-burp.jar

A Burp Suite Professional extension that exposes Burp Suite features from a REST API.

## Features
- Exposes Proxy, Scanner, Site Map, and Repeater functionalities via REST endpoints.
- Configurable IP and port for the REST server.
- API key authentication for security.
- Swagger UI documentation available at `http://<server.address>:<server.port>/`.

## Installation
1. Build the extension: `./install.sh`
2. Load `pwn-burp.jar` in Burp Suite Professional via `Extender` > `Extensions` > `Add`.
3. Install the [PWN security automation framework](https://github.com/0dayinc/pwn)

Now you can use this extension one of three ways:
1. Using PWN Driver: Execute the `pwn_burp_suite_pro_active_scan` Driver. Execute `pwn_burp_suite_pro_active_scan --help` for more information.
2. Using the `pwn` prototyping REPL: Call the #help method BurpSuite module for usage:
```
$ pwn
pwn[vX.x.nnn]:001 >>> PWN::Plugins::BurpSuite.help
```
3. Navigate to the REST API for Swagger Docs and call the API using your own solution.
  * By default, pwn-burp.jar when loaded into the Burp Suite UI runs on http://127.0.0.1:1337
  * The default can be changed via:
```
  java -Dserver.address=127.0.0.1 -Dserver.port=1337 -jar burpsuite-pro.jar
```
