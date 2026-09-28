#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把当前 git 仓库内容同步到 GitHub。

为什么不用 `git push`：本机到 github.com:443 的 git 传输会被重置
（`Connection was reset` / `Empty reply from server`），而
api.github.com 是通的。因此这里改走 **Git Data API**：
逐个文件上传 blob → 建 tree → 建 commit → 移动分支引用，
效果与 push 等价，且能绕过被阻断的传输通道。

用法：
    export GITHUB_TOKEN=ghp_xxx          # 必须：有 repo 权限的 PAT
    python scripts/sync-github.py        # 提交当前工作区并同步
    python scripts/sync-github.py -m "提交信息"

环境变量：
    GITHUB_TOKEN   必填
    GITHUB_OWNER   默认 sourcetf
    GITHUB_REPO    默认 apkguard
"""

import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

API = "https://api.github.com"
TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()
OWNER = os.environ.get("GITHUB_OWNER", "sourcetf").strip()
REPO = os.environ.get("GITHUB_REPO", "apkguard").strip()
# 网络不稳定：每个请求重试
RETRIES = 5


def die(msg):
    print("错误: " + msg, file=sys.stderr)
    sys.exit(1)


def api(method, path, body=None, ok=(200, 201, 204)):
    """调用 GitHub API，带重试。返回解析后的 JSON（或 None）。"""
    url = path if path.startswith("http") else API + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    last = ""
    for attempt in range(1, RETRIES + 1):
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", "token " + TOKEN)
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("User-Agent", "apkguard-sync")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                raw = resp.read()
                if resp.status in ok:
                    return json.loads(raw.decode("utf-8")) if raw else None
                last = "HTTP %d: %s" % (resp.status, raw[:200])
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
            last = "HTTP %d: %s" % (e.code, raw[:300])
            # 4xx（除限流）不重试
            if 400 <= e.code < 500 and e.code != 429:
                die("%s %s -> %s" % (method, path, last))
        except Exception as e:  # 网络类错误：重试
            last = str(e)
        if attempt < RETRIES:
            wait = 2 * attempt
            print("    第 %d 次失败（%s），%d 秒后重试…" % (attempt, last[:80], wait))
            time.sleep(wait)
    die("%s %s 重试 %d 次仍失败: %s" % (method, path, RETRIES, last))


def git(*args):
    out = subprocess.run(["git"] + list(args), capture_output=True)
    if out.returncode != 0:
        die("git %s 失败: %s" % (" ".join(args), out.stderr.decode("utf-8", "replace")))
    return out.stdout.decode("utf-8", "replace")


def main():
    msg = "sync"
    args = sys.argv[1:]
    if args and args[0] in ("-m", "--message"):
        msg = args[1]

    if not TOKEN:
        die("未设置 GITHUB_TOKEN 环境变量")

    # 先提交到本地仓库，再同步本地 HEAD 的内容
    subprocess.run(["git", "add", "-A"], check=True)
    if git("status", "--porcelain").strip():
        git("commit", "-m", msg)
    else:
        print("工作区无改动")

    head = git("rev-parse", "HEAD").strip()
    print("同步 commit: %s" % head[:12])

    # git ls-files -s 给出 mode/blob/sha/path
    files = []
    for line in git("ls-files", "-s").splitlines():
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        meta, path = parts
        mode, _, _ = meta.split()
        files.append((path, mode))
    if not files:
        die("没有可同步的文件（检查 .gitignore）")
    print("文件数: %d" % len(files))

    # 1) 逐个上传 blob
    tree = []
    for i, (path, mode) in enumerate(files, 1):
        with open(path, "rb") as fh:
            content = fh.read()
        blob = api("POST", "/repos/%s/%s/git/blobs" % (OWNER, REPO), {
            "content": base64.b64encode(content).decode("ascii"),
            "encoding": "base64",
        })
        tree.append({
            "path": path.replace("\\", "/"),
            "mode": "100755" if mode == "100755" else "100644",
            "type": "blob",
            "sha": blob["sha"],
        })
        if i % 20 == 0 or i == len(files):
            print("  已上传 %d/%d" % (i, len(files)))

    # 2) 建 tree
    base_tree = None
    ref = api("GET", "/repos/%s/%s/git/ref/heads/main" % (OWNER, REPO), ok=(200, 404))
    if ref and ref.get("object"):
        parent = api("GET", "/repos/%s/%s/git/commits/%s" % (OWNER, REPO, ref["object"]["sha"]))
        base_tree = parent.get("tree", {}).get("sha")
        print("原有 HEAD: %s" % ref["object"]["sha"][:12])

    body = {"tree": tree}
    if base_tree:
        body["base_tree"] = base_tree
    new_tree = api("POST", "/repos/%s/%s/git/trees" % (OWNER, REPO), body)
    print("tree: %s" % new_tree["sha"][:12])

    # 3) 建 commit
    commit_body = {"message": msg, "tree": new_tree["sha"]}
    if ref and ref.get("object"):
        commit_body["parents"] = [ref["object"]["sha"]]
    commit = api("POST", "/repos/%s/%s/git/commits" % (OWNER, REPO), commit_body)
    print("commit: %s" % commit["sha"][:12])

    # 4) 移动分支引用
    if ref and ref.get("object"):
        api("PATCH", "/repos/%s/%s/git/refs/heads/main" % (OWNER, REPO), {"sha": commit["sha"]})
    else:
        api("POST", "/repos/%s/%s/git/refs" % (OWNER, REPO),
            {"ref": "refs/heads/main", "sha": commit["sha"]})

    print("完成：https://github.com/%s/%s" % (OWNER, REPO))


if __name__ == "__main__":
    main()