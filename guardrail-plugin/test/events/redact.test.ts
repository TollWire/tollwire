import { describe, expect, it } from "vitest";
import { redactCommand, redactText, secretName } from "../../src/events/redact.js";

const red = (command: string): { text: string; redactions: number } => {
  const r = redactCommand(command);
  if (r === null) throw new Error("not parsable");
  return r;
};

// Synthetic values only; none of these is a real credential.
const GH = `ghp_${"a1B2".repeat(9)}`;
const AWS = ["AKIA", "ABCDEFGHIJKLMNOP"].join("");

describe("name-value pairs", () => {
  it.each([
    ["curl --pass''word=hunter2 https://x", "curl --password=[REDACTED:credential] https://x"],
    ["curl --$'pass'word=hunter2 https://x", "curl --password=[REDACTED:credential] https://x"],
    ["export MY_API_KEY=abc", "export MY_API_KEY=[REDACTED:credential]"],
    ["GITHUB_TOKEN=abc npm publish", "GITHUB_TOKEN=[REDACTED:credential] npm publish"],
    ["X_SECRET_KEY=1 run", "X_SECRET_KEY=[REDACTED:credential] run"],
    ["PGPASSWORD=x psql", "PGPASSWORD=[REDACTED:credential] psql"],
    ["run --api-key abc", "run --api-key [REDACTED:credential]"],
    ["run --api-key=abc", "run --api-key=[REDACTED:credential]"],
    ["run --apiKey abc", "run --apiKey [REDACTED:credential]"],
    ["run --passphrase 'a b'", "run --passphrase [REDACTED:credential]"],
    ["docker run -eAPI_KEY=abc img", "docker run -eAPI_KEY=[REDACTED:credential] img"],
    ["docker run -e DB_PASSWORD=abc img", "docker run -e DB_PASSWORD=[REDACTED:credential] img"],
    ["curl -d 'password=abc&x=1' u", "curl -d password=[REDACTED:credential] u"],
    ["curl 'https://x/?id=1&token=abc&y=2'", "curl https://x/?id=1&token=[REDACTED:credential]&y=2"],
  ])("%s", (input, expected) => {
    const r = red(input);
    expect(r.text).toBe(expected);
    expect(r.redactions).toBe(1);
  });
  it.each([
    "git commit --author='A <a@b>' -m x",
    "GIT_AUTHOR_NAME=x git commit",
    "run --bypass x",
    "compass=1 run",
    "passthrough=1 run",
    "keyboard=1 run",
    "run --tokenizer x",
    "run --key-file f",
    "run --keyring x",
    "run TOKEN=",
    "run --password",
    "run --password --other",
    "wget -H http://x",
  ])("counter-example without a hit: %s", (input) => {
    const r = red(input);
    expect(r.redactions).toBe(0);
    expect(r.text).not.toContain("REDACTED");
  });
  it("matches a name split by a format character", () => {
    const r = red("run --pass​word=x");
    expect(r.text).toContain("=[REDACTED:credential]");
    expect(r.redactions).toBe(1);
  });
  it("splits names at underscores, hyphens, dots and camel case", () => {
    for (const name of ["token", "TOKEN", "my.token", "my-token", "myToken", "MyToken", "APIKey", "x_auth", "Authorization", "credentials", "cookie", "pwd", "passwd", "secret", "PGPASSWORD", "DBPASSWORD", "apikey", "ssh_key", "--client-secret"]) {
      expect(secretName(name), name).toBe(true);
    }
    for (const name of ["author", "bypass", "compass", "passthrough", "keyboard", "tokenizer", "key_file", "monkeys", "path", ""]) {
      expect(secretName(name), name).toBe(false);
    }
  });
});

describe("headers, users and URLs", () => {
  it.each([
    ["curl -HAuthorization:Bearer\\ abc https://x", "curl -HAuthorization:[REDACTED:header] https://x"],
    ["curl -H 'X-Amz-Security-Token: abc' https://x", "curl -H X-Amz-Security-Token: [REDACTED:header] https://x"],
    ["curl --header 'Cookie: a=b' https://x", "curl --header Cookie: [REDACTED:header] https://x"],
    ["curl --header='Private-Token: abc' https://x", "curl --header=Private-Token: [REDACTED:header] https://x"],
    ["wget --header='Authorization: Basic abc' https://x", "wget --header=Authorization: [REDACTED:header] https://x"],
    ["curl -H 'x-api-key: abc' https://x", "curl -H x-api-key: [REDACTED:header] https://x"],
    ["curl -H 'X-Vault-Token: abc' u", "curl -H X-Vault-Token: [REDACTED:header] u"],
    ["curl -H 'X-Goog-Api-Key: abc' u", "curl -H X-Goog-Api-Key: [REDACTED:header] u"],
    ["curl -H 'Proxy-Authorization: abc' u", "curl -H Proxy-Authorization: [REDACTED:header] u"],
    ["curl -H 'X-Auth-Token: abc' u", "curl -H X-Auth-Token: [REDACTED:header] u"],
    ["curl -H 'Api-Key: abc' u", "curl -H Api-Key: [REDACTED:header] u"],
    ["http POST x Authorization:Bearer\\ abc", "http POST x Authorization:[REDACTED:header]"],
  ])("%s", (input, expected) => {
    const r = red(input);
    expect(r.text).toBe(expected);
    expect(r.redactions).toBe(1);
  });
  it("leaves harmless headers alone", () => {
    expect(red("curl -H 'Accept: text/html' u")).toEqual({ text: "curl -H Accept: text/html u", redactions: 0 });
  });
  it.each([
    ["curl -u user:pass https://x", "curl -u [REDACTED:credential] https://x"],
    ["curl -uuser:pass https://x", "curl -u[REDACTED:credential] https://x"],
    ["curl --user user:pass https://x", "curl --user [REDACTED:credential] https://x"],
    ["curl --user=user:pass https://x", "curl --user=[REDACTED:credential] https://x"],
    ["curl --proxy-user u:p https://x", "curl --proxy-user [REDACTED:credential] https://x"],
  ])("%s", (input, expected) => {
    const r = red(input);
    expect(r.text).toBe(expected);
    expect(r.redactions).toBe(1);
  });
  it("replaces user info in URLs", () => {
    expect(red("git clone https://u:p@h/r.git")).toEqual({ text: "git clone https://[REDACTED:userinfo]@h/r.git", redactions: 1 });
    expect(red("git clone ssh://token@h/r.git").text).toBe("git clone ssh://[REDACTED:userinfo]@h/r.git");
    expect(red("git clone https://h/r.git@x").redactions).toBe(0);
  });
});

describe("known programs", () => {
  it.each([
    ["mysql -uroot -pSECRET db", "mysql -uroot -p[REDACTED:password] db"],
    ["mysqldump -pSECRET db", "mysqldump -p[REDACTED:password] db"],
    ["sshpass -p secret ssh host", "sshpass -p [REDACTED:password] ssh host"],
    ["sshpass -psecret ssh host", "sshpass -p[REDACTED:password] ssh host"],
    ["docker login -u me -p pw", "docker login -u me -p [REDACTED:password]"],
    ["htpasswd -b file user pw", "htpasswd -b file user [REDACTED:password]"],
    ["htpasswd -nb user pw", "htpasswd -nb user [REDACTED:password]"],
    ["openssl enc -aes256 -pass pass:abc -in f", "openssl enc -aes256 -pass pass:[REDACTED:password] -in f"],
    ["openssl enc -passin pass:abc", "openssl enc -passin pass:[REDACTED:password]"],
    ["aws configure set aws_secret_access_key XYZ", "aws configure set aws_secret_access_key [REDACTED:credential]"],
    ["aws configure set aws_session_token XYZ", "aws configure set aws_session_token [REDACTED:credential]"],
  ])("%s", (input, expected) => {
    const r = red(input);
    expect(r.text).toBe(expected);
    expect(r.redactions).toBe(1);
  });
  it("does not redact prompts and harmless options", () => {
    expect(red("mysql -p db").redactions).toBe(0);
    expect(red("aws configure set region eu-west-1").redactions).toBe(0);
    expect(red("docker login -u me").redactions).toBe(0);
    expect(red("htpasswd file user").redactions).toBe(0);
    expect(red("grep -pSECRET x").redactions).toBe(0);
  });
  it("sees through wrappers", () => {
    expect(red("sudo -u root mysql -pSECRET").text).toBe("sudo -u root mysql -p[REDACTED:password]");
    expect(red("env X=1 sshpass -p pw ssh h").text).toBe("env X=1 sshpass -p [REDACTED:password] ssh h");
  });
});

describe("secret formats", () => {
  it("masks prefix-anchored formats anywhere in a word", () => {
    expect(red(`echo ${GH}`)).toEqual({ text: "echo [REDACTED:secret]", redactions: 1 });
    expect(red(`echo x${AWS}y`).redactions).toBe(0); // \b anchored: embedded in a longer word
    expect(red(`echo ${AWS}`).text).toBe("echo [REDACTED:secret]");
    expect(red(`echo ${["-----BEGIN RSA ", "PRIVATE KEY-----"].join("")}`).text).toBe("echo [REDACTED:secret]");
    expect(red(`echo sk-ant-${"x".repeat(30)}`).text).toBe("echo [REDACTED:secret]");
    expect(red(`echo npm_${"a".repeat(36)}`).text).toBe("echo [REDACTED:secret]");
    expect(red(`echo glpat-${"a".repeat(24)}`).text).toBe("echo [REDACTED:secret]");
  });
  it("redactText masks formats and user info in free text", () => {
    expect(redactText(`reason with ${GH} and https://u:p@h/x`)).toEqual({
      text: "reason with [REDACTED:secret] and https://[REDACTED:userinfo]@h/x",
      redactions: 2,
    });
    expect(redactText("nothing to see")).toEqual({ text: "nothing to see", redactions: 0 });
  });
});

describe("structure of the logged text", () => {
  it("joins simple commands with ' ; ' and drops comments", () => {
    expect(red("ls -la # token=abc\nwc -l f").text).toBe("ls -la ; wc -l f");
  });
  it("keeps redirections", () => {
    expect(red("echo hi > out.txt").text).toBe("echo hi > out.txt");
    expect(red("echo hi 2>&1").text).toContain("echo hi");
  });
  it("replaces here-document bodies", () => {
    expect(red("cat <<EOF\npassword=hunter2\nEOF")).toEqual({ text: "cat << EOF [REDACTED:heredoc]", redactions: 1 });
    expect(red("cat <<'EOF'\n\nEOF").text).not.toContain("hunter2");
  });
  it("summarizes substitutions and redacts the nested command", () => {
    expect(red("echo $(curl -u a:b x)")).toEqual({ text: "curl -u [REDACTED:credential] x ; echo $(…)", redactions: 1 });
    expect(red("echo `whoami` > f").text).toBe("whoami ; echo `…` > f");
    expect(red("diff <(sort a) b").text).toBe("sort a ; diff <(…) b");
    expect(red("echo $(echo $(echo x)) y").text).toContain("echo $(…) y");
  });
  it("returns null if the command cannot be tokenized", () => {
    expect(redactCommand("echo 'open")).toBeNull();
    expect(redactCommand("echo \"open")).toBeNull();
  });
  it("handles an empty command", () => {
    expect(redactCommand("")).toEqual({ text: "", redactions: 0 });
  });
  it("treats unterminated substitution text defensively", () => {
    expect(redactCommand("echo $(")).toBeNull();
  });
});

describe("further heuristics (security review finding 2)", () => {
  it.each([
    [`curl -d '{"password":"hunter2","user":"bob"}' u`, `curl -d {"password":"[REDACTED:credential]","user":"bob"} u`],
    [`curl -d '{"user":"bob", "api_key" : "abc\\"def"}' u`, `curl -d {"user":"bob", "api_key" : "[REDACTED:credential]"} u`],
    [`curl --data '{"auth":{"clientSecret":"x1"}}' u`, `curl --data {"auth":{"clientSecret":"[REDACTED:credential]"}} u`],
  ])("JSON key scan: %s", (input, expected) => {
    const r = red(input);
    expect(r.text).toBe(expected);
    expect(r.redactions).toBe(1);
  });
  it("leaves harmless JSON and already redacted values alone", () => {
    expect(red(`curl -d '{"name":"bob","count":"3"}' u`).redactions).toBe(0);
    expect(redactText('{"password":"[REDACTED:credential]"}').redactions).toBe(0);
  });
  it("applies the JSON key scan to free text", () => {
    expect(redactText('body {"token": "abc"} sent')).toEqual({ text: 'body {"token": "[REDACTED:credential]"} sent', redactions: 1 });
  });
  it.each([
    ["redis-cli -h host -a hunter2 ping", "redis-cli -h host -a [REDACTED:password] ping"],
    ["ldapsearch -x -D cn=admin -w hunter2 -b dc=x", "ldapsearch -x -D cn=admin -w [REDACTED:password] -b dc=x"],
    ["ldapsearch -x -whunter2 -b dc=x", "ldapsearch -x -w[REDACTED:password] -b dc=x"],
    ["ldapmodify -w hunter2 -f x.ldif", "ldapmodify -w [REDACTED:password] -f x.ldif"],
    ["openssl enc -aes-256-cbc -k hunter2 -in f", "openssl enc -aes-256-cbc -k [REDACTED:password] -in f"],
    ["sudo redis-cli -a hunter2", "sudo redis-cli -a [REDACTED:password]"],
    ["curl --oauth2-bearer abc123 https://x", "curl --oauth2-bearer [REDACTED:credential] https://x"],
    ["run --bearer=abc123", "run --bearer=[REDACTED:credential]"],
  ])("short option or bearer: %s", (input, expected) => {
    const r = red(input);
    expect(r.text).toBe(expected);
    expect(r.redactions).toBe(1);
  });
  it("does not redact the same letters for other programs or prompts", () => {
    expect(red("grep -a foo f").redactions).toBe(0);
    expect(red("ls -w 80").redactions).toBe(0);
    expect(red("ldapsearch -W -x").redactions).toBe(0);
    expect(red("redis-cli -h host ping").redactions).toBe(0);
    expect(red("openssl x509 -k").redactions).toBe(0);
    expect(secretName("bearer")).toBe(true);
  });
});
