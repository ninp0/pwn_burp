# PwnBurpRestApi

A Burp Suite Professional extension that exposes features via a REST API.

## Features
- Exposes Proxy, Scanner, Site Map, and Repeater functionalities via REST endpoints.
- Configurable IP and port for the REST server.
- API key authentication for security.
- Swagger UI documentation available at `http://<server.address>:<server.port>/`.

## Installation
1. Build the extension: `./install.sh`
2. Load `pwn-burp.jar` in Burp Suite Professional via `Extender` > `Extensions` > `Add`.
3. Configure settings in `config.properties` or via system properties:
```
  java -Dserver.address=0.0.0.0 -Dserver.port=8081 -Dapikey=your-secret-key -jar burpsuite-pro.jar
```
4. Add the pwn-burp.jar to the Burp Suite extensions that's located in /opt/burpsuite/pwn-burp.jar
