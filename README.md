# CPAWall prototype

CPAWall (Cross-Project Authority Wall) is the system of the paper
"Cross-Project Authority Leakage in LLM Agent Platforms and How to
Contain It" (W. Han and S. Baek). This is its prototype, built to the
authors' design document (design-v0.4.2); the code keeps the system's
working name, `bulkhead`, as the name of its Python package. Every
project gets its own partition, one reference policy is enforced on
every channel, and a hash-chained log feeds an auditor. It runs on Linux
only, because it uses user and network namespaces and Landlock.
Milestone status and reports are in [`MILESTONES.md`](MILESTONES.md).

The code is published at https://github.com/iamhwk/CPAWall under the
Apache License 2.0 ([License](#license)); that repository is updated
from the authors' working repository.

## Layout

```
bulkhead/            the system
  decisions.py       deny < ask < allow; meet and join
  env.py             CA and proxy variables that clients read
  agent/             scripted agent (JSON scripts of tool calls), tool servers
  policy/            patterns, request mapping, manifest schema, compiler, analyzer
  core/              PDP (versions, approvals), vault, hash-chained log,
                     session manager, trusted UI and its channel, auditor
  pep/               HTTP(S) PEP, deployment CA, partitions (sandbox, Landlock)
testbed/             HTTPS services on loopback with per-project credentials
  services.py        git host (smart HTTP, issues), cloud API, staging DB, chat
  setup.py           repositories, credentials, canaries, substrates, sign-in
  tls.py             the testbed's CA
  ontology.yaml      request mapping for the testbed's sites (development aid)
  manifests/         the running example's manifests (design, Figure 6)
eval/
  probes/            one JSON script per probe: conditions, steps, judgment
  run_eval.py        runs probes under a configuration, one JSON line per trial
  walkthrough.py     the paper's walkthrough, by hand (see below)
tests/               unittest suites
pilot/               harness and records of the pilot on a deployed coding
                     agent (paper, opening of Section VI); see pilot/README.md
```

## Running

You need Python 3.13 and `pip install -r requirements.txt`. The testbed
also needs two things from the host:

- Its host names in `/etc/hosts`. `testbed.setup.ensure_hosts()` adds them
  when the file is writable. Otherwise add these lines:
  ```
  127.77.0.1 git.test
  127.77.0.2 cloud.test
  127.77.0.3 db.test
  127.77.0.4 chat.test
  ```
- Permission to bind port 443 on those addresses, as root or after
  `sysctl net.ipv4.ip_unprivileged_port_start=0`.

Partitions also need Landlock and unprivileged user namespaces. Ubuntu
24.04 restricts the latter through AppArmor; allow them with
`sysctl kernel.apparmor_restrict_unprivileged_userns=0`. The browser in
a partition additionally needs Playwright's headless Chromium shell and
`certutil` (libnss3-tools).

```
python -m unittest discover -s tests -t .
python -m eval.run_eval --workdir /tmp/bh --config bulkhead --reps 5 eval/probes/*.json
python -m bulkhead.policy.analyzer --ontology testbed/ontology.yaml \
    --inventory testbed/inventory.yaml testbed/manifests/*.yaml
python -m bulkhead.core.audit --state /tmp/bh/core --service-log /tmp/bh/srv/access.jsonl
python -m bulkhead.core.ui authority --state /tmp/bh/core --ontology testbed/ontology.yaml
```

A run with a Bulkhead core prints the auditor's checks (C1–C5) for that
run on standard error.
The paper (from v0.9.3) calls these checks V1–V5 and names the three
conditions C1–C3; the code and the design document keep C1–C5 for the
checks and P1–P3 for the conditions.

Configurations (`eval/runtimes.py`):

- `baseline`: the shared substrate.
- `pep-shared`: the same, with every HTTP(S) request through the
  project's PEP (ablation: no partitions).
- `capscope`: a CapScope-style harness on the shared substrate, with
  path and argument-prefix capabilities minted from the trusted task.
- `simple-isolation`: one container per project, with no policy.
- `bulkhead`: a partition per project.
- `bulkhead-perchannel`, `bulkhead-noversions`, `bulkhead-nolabels`:
  ablations of Bulkhead.

The whole scripted evaluation, its tables and the overhead benchmarks:

```
python -m eval.campaign --workdir /tmp/bh-work --out /tmp/bh-out --reps 5
python -m eval.report /tmp/bh-out/results.jsonl.gz   # or read tables.md
python -m eval.bench --workdir /tmp/bh-bench --scale 5
```

Load and scalability (throughput, number of projects, policy size, log
and audit, sessions, work inside partitions, and a replay of the model
trials' tool calls), with its tables:

```
python -m eval.scale --workdir /tmp/bh-scale --out /tmp/bh-scale.json
python -m eval.scale --workdir /tmp/bh-scale --out /tmp/bh-scale.json --report
```

Model-driven trials (M6b) let a model choose its own tool calls on the
prompts in `eval/model_probes/`, through the same configurations. They
need an Anthropic API key, read from `ANTHROPIC_API_KEY` or from the file
`~/.config/bulkhead/anthropic_api_key`, and cost money (the M6b campaign,
400 trials with two models, cost about US$3.3; `--budget` stops a run
above a limit):

```
python -m eval.model_eval --workdir /tmp/bh-model --out /tmp/bh-model-out \
    --model claude-haiku-5-5 --reps 5 --budget 1
python -m eval.model_report /tmp/bh-model-out/results-claude-haiku-5-5.jsonl
```

The testbed never touches a real service. Every credential and secret in
it is generated for each instance; the secrets are canaries.

## Walkthrough: try it by hand

`eval/walkthrough.py` runs the running example (paper, Section 5.1)
interactively: the testbed's services, Bulkhead's core for projects OSS
and Work, and the trusted UI. It needs the same host as the tests: Linux
with Landlock (kernel 5.13 or later; Ubuntu 24.04 has it), Python 3.13,
git, and the host settings of [Running](#running). macOS and Windows
cannot run it directly. The two `sysctl` settings loosen the host's
defaults, so a dedicated Ubuntu 24.04 virtual machine is the best place
for it. On a fresh one:

```
sudo add-apt-repository -y ppa:deadsnakes/ppa      # Python 3.13 for Ubuntu 24.04
sudo apt install -y git python3.13 python3.13-venv
git clone https://github.com/iamhwk/CPAWall
cd CPAWall
python3.13 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
printf '%s\n' "127.77.0.1 git.test" "127.77.0.2 cloud.test" \
  "127.77.0.3 db.test" "127.77.0.4 chat.test" | sudo tee -a /etc/hosts
sudo sysctl -w net.ipv4.ip_unprivileged_port_start=0            # the services listen on port 443
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0   # partitions need user namespaces
```

The `sysctl` settings last until the next reboot. To restore them sooner:

```
sudo sysctl -w net.ipv4.ip_unprivileged_port_start=1024
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=1
```

Then open two terminals in that folder and activate the venv in both
(`. .venv/bin/activate`):

```
terminal 1:  python -m eval.walkthrough --workdir /tmp/bh-walk
terminal 2:  python -m bulkhead.core.ui console --state /tmp/bh-walk/core
```

Terminal 1 is a shell prompt in the active project's partition: each line
runs there as code the agent runs would, and counts as one task. The
console in terminal 2 is the trusted UI, the only place where projects
are switched and approvals answered; it also takes `status` and `help`.
Terminal 1 prints the steps; in short:

| Where | Type | What happens |
|---|---|---|
| UI | `switch oss` | OSS becomes the active project |
| shell | Enter, then `git clone https://git.test/acme/payments.git /tmp/payments` | refused (403): OSS's policy grants nothing on Work's repository |
| shell | `cat ~/.git-credentials` | no such file: OSS's partition holds no credential (on a shared OS account, git's store would hold Work's) |
| UI | `switch work` | Work becomes active; OSS is frozen |
| shell | Enter, `cd work/payments`, then `git commit --allow-empty -m walkthrough && git push` | the push waits: the shell's own setting allows pushes, but Work's policy says ask |
| UI | `#1 work asks to push repo://git.test/acme/payments ...` appears; type `t` (or `n`) | the push goes through for this task (or is refused, 403) |
| shell | `cat secrets/staging.env` | no such file: the policy hides Work's secrets from every channel |
| UI, shell | `status`, then `exit` | the state of both projects; `exit` stops the core, the partitions and the services |

The shell's prompt shows the project that was active when the prompt was
printed, so press Enter after a switch. A question nobody answers within
five minutes is denied (`--timeout` changes this).
`python -m bulkhead.core.ui switch work` and `... status` do the same as
the console's commands, once.

Afterwards, the reports and the auditor read what the run left behind:

```
python -m bulkhead.core.ui log --state /tmp/bh-walk/core -n 20
python -m bulkhead.core.ui verify --state /tmp/bh-walk/core
python -m bulkhead.core.ui authority --state /tmp/bh-walk/core --ontology testbed/ontology.yaml
python -m bulkhead.core.audit --state /tmp/bh-walk/core --service-log /tmp/bh-walk/srv/access.jsonl
```

The auditor prints C1–C5, which the paper calls V1–V5. To start over,
delete `/tmp/bh-walk`.

## 직접 해 보기 (Walkthrough 한국어 안내)

`eval/walkthrough.py`는 논문 5.1절의 예시(프로젝트 OSS와 Work)를 손으로
따라 해 보는 실행 파일입니다. 실험용 서비스, Bulkhead 코어, 파티션,
trusted UI를 한꺼번에 띄웁니다.

### 필요한 환경

리눅스, 그중 **Ubuntu 24.04**를 권합니다. 프로젝트별 격리에 리눅스 커널
기능(네임스페이스, Landlock)을 쓰기 때문에 맥과 윈도우에서는 바로 실행되지
않습니다. 아래 `sysctl` 설정이 시스템 보안을 조금 느슨하게 하므로, 연습용
가상 머신(VirtualBox, UTM, 클라우드 VM 등)을 하나 만들어 쓰는 것이 좋습니다.
WSL2에서는 확인하지 않았습니다.

### 1. 한 번만 하는 준비

```
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt install -y git python3.13 python3.13-venv
git clone https://github.com/iamhwk/CPAWall
cd CPAWall
python3.13 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
printf '%s\n' "127.77.0.1 git.test" "127.77.0.2 cloud.test" \
  "127.77.0.3 db.test" "127.77.0.4 chat.test" | sudo tee -a /etc/hosts
sudo sysctl -w net.ipv4.ip_unprivileged_port_start=0            # 실험 서비스가 443 포트를 씀
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0   # 파티션 생성 허용
```

`sysctl` 두 줄은 재부팅하면 원래대로 돌아갑니다. 그 전에 되돌리려면
`ip_unprivileged_port_start=1024`, `apparmor_restrict_unprivileged_userns=1`로
다시 설정합니다.

### 2. 터미널 두 개 열기

둘 다 받은 `CPAWall` 폴더에서 `. .venv/bin/activate`를 먼저 실행합니다.

```
터미널 1:  python -m eval.walkthrough --workdir /tmp/bh-walk
           # 활성 프로젝트의 파티션 안에서 도는 셸 (에이전트가 실행하는 코드 역할)
터미널 2:  python -m bulkhead.core.ui console --state /tmp/bh-walk/core
           # Trusted UI
```

### 3. 따라 해 보기

| 어디서 | 입력 | 결과 |
|---|---|---|
| UI | `switch oss` | OSS가 활성 프로젝트가 됨 |
| 셸 | Enter 후 `git clone https://git.test/acme/payments.git /tmp/payments` | **403으로 거부.** OSS 정책은 회사 저장소에 아무 권한도 주지 않음 |
| 셸 | `cat ~/.git-credentials` | 파일 없음. OSS 파티션에는 Work 자격 증명이 아예 없음 (OS 계정을 함께 쓰면 여기에 Work의 것이 남음) |
| UI | `switch work` | Work가 활성 프로젝트가 되고 OSS는 정지됨 |
| 셸 | Enter 후 `cd work/payments`, 이어서 `git commit --allow-empty -m walkthrough && git push` | push가 멈춰서 기다림. 셸 설정은 push를 허용하지만 Work 정책이 ask이기 때문 |
| UI | 질문 `#1 work asks to push ...`가 뜸 → `t` 입력 (거부하려면 `n`) | push 성공 (`n`이면 403) |
| 셸 | `cat secrets/staging.env` | 파일 없음. Work 정책이 비밀 파일을 셸에서도 숨김 |
| UI / 셸 | `status` / `exit` | 상태 확인 / 코어·파티션·서비스 전체 종료 |

셸 프롬프트에는 프롬프트를 찍은 시점의 프로젝트가 보이므로, UI에서 전환한
뒤에는 셸에서 Enter를 한 번 누르세요. 5분 안에 답하지 않은 질문은 자동으로
거부됩니다(`--timeout`으로 바꿀 수 있음).

### 4. 끝난 뒤 기록 확인

```
python -m bulkhead.core.ui log --state /tmp/bh-walk/core -n 20      # 결정 기록
python -m bulkhead.core.ui verify --state /tmp/bh-walk/core         # 로그 위변조 검사
python -m bulkhead.core.audit --state /tmp/bh-walk/core --service-log /tmp/bh-walk/srv/access.jsonl
```

감사기 출력의 C1–C5는 논문의 V1–V5와 같습니다(코드는 예전 이름을 그대로
씁니다). 처음부터 다시 하려면 `/tmp/bh-walk`를 지우면 됩니다.

## License

Licensed under the Apache License, Version 2.0 ([`LICENSE`](LICENSE)).
The copyright notice is in [`NOTICE`](NOTICE).
