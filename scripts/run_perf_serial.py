#!/usr/bin/env python3

import os
import re
import shlex
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


SUMMARY_PATTERN = re.compile(
    r"^(===|  Setup:|  Blocking:|  Cascade:|  Cascade rate:|  Total:|"
    r"  Wall time:|  Messages:|  Msgs/s:|  Peak RSS:|  Slices/s:|"
    r"  Messages/peer:|  Current RSS:|  Budget:|  RSS before:|  RSS after:|"
    r"  RSS delta:|  Seeded keys:|  Lookups:|  Alice messages:|  Bob messages:|"
    r"  [A-Za-z0-9_-]+ peak RSS:|  P[0-9]+ peak RSS:|  Catchup wall|"
    r"  Leaf daemons:|  Total nodes:|  Lowmem:|  Hub messages:|  Messages/leaf:|"
    r"  Total deliveries:|  Deliveries/s:|  Hub RSS|  Leaf RSS|  Hub threads:|"
    r"  Leaf threads:|  Hub FDs:|  Leaf FDs:|  Hub maps:|  Leaf maps:|"
    r"  Events/s|  MB/s:|  Total attributed:|  Throughput:|  Tail converge|"
    r"  All converge|  Hop latency|  Delivery|  Live rate|  Live duration|"
    r"  Peers:|  Preload|  Remote deliveries|  Stage breakdown|  Progress windows|"
    r"    sent |Generated|RUN_DIR=|SCENARIO=|DELTA_KIND=|"
    r"BASE_EVENTS=|DELTA_EVENTS=|DELTA_FILES=|DELTA_FILE_SIZE_MIB=|"
    r"DELTA_FILE_SLICES_EXPECTED=|PRE_DELTA_MESSAGES=|POST_DELTA_MESSAGES=|"
    r"DELTA_MESSAGES_OBSERVED=|PRE_DELTA_FILE_SLICES=|POST_DELTA_FILE_SLICES=|"
    r"DELTA_FILE_SLICES_OBSERVED=|DELTA_MARKER_PREFIX=|DELTA_MARKERS_EXPECTED=|"
    r"DELTA_MARKERS_SYNCED=|ALICE_PEAK_VMHWM_MIB=|BOB_PEAK_VMHWM_MIB=|"
    r"BOB_PEAK_RSS_MIB=|MAX_BOB_TOTAL_MIB=|MAX_BOB_TOTAL_KB=|LOWMEM_BUDGET_KB=|"
    r"PASS_UNDER_24MB=|CGROUP_ENFORCED=|"
    r"CGROUP_LIMIT_KB=|CGROUP_OOM=|CGROUP_OOM_KILL=|MAX_BOB_ANON_KB=|"
    r"MAX_BOB_ANON_UNLABELED_KB=|MAX_BOB_DB_SHM_KB=|MAX_BOB_DB_WAL_KB=|"
    r"MAX_SQLITE_MEM_CUR=|MAX_SQLITE_MEM_HIGH=|MAX_MALL_ARENA=|MAX_MALL_USED=|"
    r"MAX_MALL_FREE=|MAX_MALL_MMAP=|MAX_INIT_WANTED=|MAX_INIT_NEED_QUEUE=|"
    r"MAX_DATA_EVENTS_INGESTED=|MAX_DATA_BLOB=|MEMTRACE_PRESENT=)"
)


class PerfRunner:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.write_perf_md = os.environ.get("WRITE_PERF_MD", "1") == "1"
        self.script_dir = Path(__file__).resolve().parent
        self.repo_root = self.script_dir.parent
        self.perf_md = self.repo_root / "docs" / "PERF.md"
        self.lowmem_script = self.repo_root / "scripts" / "run_lowmem.sh"
        self.auto_results: list[str] = []
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmpdir.name)

    def env_value(self, name: str, default: str) -> str:
        return os.environ.get(name, default)

    def render_cmd(self, args: list[str]) -> str:
        return shlex.join(args)

    def append_auto_result_from_log(self, label: str, cmd_rendered: str, log_text: str) -> None:
        matches = [line for line in log_text.splitlines() if SUMMARY_PATTERN.search(line)]
        body = "\n".join(matches) if matches else log_text.rstrip()
        if body:
            body += "\n"
        self.auto_results.append(
            f"### {label}\n\n```bash\n{cmd_rendered}\n```\n\n```text\n{body}```\n"
        )

    def append_auto_result_raw(self, label: str, cmd_rendered: str, summary_text: str) -> None:
        body = summary_text.rstrip()
        if body:
            body += "\n"
        self.auto_results.append(
            f"### {label}\n\n```bash\n{cmd_rendered}\n```\n\n```text\n{body}```\n"
        )

    def run(
        self,
        label: str,
        args: list[str],
        *,
        extra_env: dict[str, str] | None = None,
        allow_failure: bool = False,
    ) -> None:
        env = os.environ.copy()
        if extra_env:
            env.update(extra_env)
        cmd_rendered = self.render_cmd(args)
        print(f"\n>>> {cmd_rendered}", flush=True)
        proc = subprocess.run(
            args,
            cwd=self.repo_root,
            env=env,
            capture_output=True,
            text=True,
        )
        output = proc.stdout + proc.stderr
        if output:
            print(output, end="" if output.endswith("\n") else "\n", flush=True)
        if proc.returncode != 0 and not allow_failure:
            raise subprocess.CalledProcessError(proc.returncode, args)
        if self.write_perf_md:
            text = output.rstrip()
            if proc.returncode != 0:
                text += f"\ncommand exited with status {proc.returncode}\n"
            self.append_auto_result_from_log(label, cmd_rendered, text)

    def run_live_with_summary(
        self,
        label: str,
        summary_path: Path,
        args: list[str],
    ) -> None:
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        if summary_path.exists():
            summary_path.unlink()
        cmd_rendered = self.render_cmd(args)
        print(f"\n>>> {cmd_rendered}", flush=True)
        proc = subprocess.run(args, cwd=self.repo_root)
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, args)
        if self.write_perf_md:
            if not summary_path.exists():
                raise RuntimeError(f"missing benchmark summary file: {summary_path}")
            self.append_auto_result_raw(label, cmd_rendered, summary_path.read_text())

    def run_capture(
        self,
        label: str,
        args: list[str],
        *,
        extra_env: dict[str, str] | None = None,
        allow_failure: bool = False,
        summary_path: Path | None = None,
    ) -> None:
        env = os.environ.copy()
        if extra_env:
            env.update(extra_env)
        if summary_path is not None:
            summary_path.parent.mkdir(parents=True, exist_ok=True)
            if summary_path.exists():
                summary_path.unlink()
        cmd_rendered = self.render_cmd(args)
        print(f"\n>>> {cmd_rendered}", flush=True)
        proc = subprocess.run(
            args,
            cwd=self.repo_root,
            env=env,
            capture_output=True,
            text=True,
        )
        output = proc.stdout + proc.stderr
        if output:
            print(output, end="" if output.endswith("\n") else "\n", flush=True)
        if proc.returncode != 0 and not allow_failure:
            raise subprocess.CalledProcessError(proc.returncode, args)

        if self.write_perf_md:
            if proc.returncode == 0 and summary_path is not None and summary_path.exists():
                self.append_auto_result_raw(label, cmd_rendered, summary_path.read_text())
            else:
                failure_text = output.rstrip()
                if proc.returncode != 0:
                    failure_text += (
                        f"\ncommand exited with status {proc.returncode}\n"
                    )
                self.append_auto_result_from_log(label, cmd_rendered, failure_text)

    def run_lowmem_matrix(self) -> None:
        budget_kb = self.env_value("PERF_LOWMEM_BUDGET_KB", "24576")
        cgroup_enforce = self.env_value("PERF_LOWMEM_CGROUP_ENFORCE", "1")
        cgroup_limit_kb = self.env_value("PERF_LOWMEM_CGROUP_LIMIT_KB", "22528")
        base_small = self.env_value("PERF_LOWMEM_BASELINE_SMALL", "50000")
        base_bracket = self.env_value("PERF_LOWMEM_BASELINE_BRACKET", "100000")
        base_large = self.env_value("PERF_LOWMEM_BASELINE_LARGE", "500000")
        delta_target = self.env_value("PERF_LOWMEM_DELTA_TARGET", "10000")
        delta_bracket = self.env_value("PERF_LOWMEM_DELTA_BRACKET", "50000")
        file_baseline = self.env_value("PERF_LOWMEM_FILE_BASELINE", "50000")
        file_count = self.env_value("PERF_LOWMEM_FILE_COUNT", "20")
        file_size_mib = self.env_value("PERF_LOWMEM_FILE_SIZE_MIB", "1")

        if self.env_value("PERF_LOWMEM_RUN_SMALL_TARGET", "1") == "1":
            self.run(
                f"Lowmem Delta ({base_small}+{delta_target} messages)",
                [str(self.lowmem_script), "delta10k"],
                extra_env={
                    "LOWMEM_BASE_EVENTS": base_small,
                    "LOWMEM_DELTA_EVENTS": delta_target,
                    "LOWMEM_BUDGET_KB": budget_kb,
                    "LOWMEM_CGROUP_ENFORCE": cgroup_enforce,
                    "LOWMEM_CGROUP_LIMIT_KB": cgroup_limit_kb,
                },
                allow_failure=True,
            )

        if self.env_value(
            "PERF_LOWMEM_RUN_BRACKET",
            self.env_value("PERF_LOWMEM_RUN_SMALL_BRACKET", "0"),
        ) == "1":
            self.run(
                f"Lowmem Delta ({base_bracket}+{delta_bracket} messages, slow opt-in)",
                [str(self.lowmem_script), "delta10k"],
                extra_env={
                    "LOWMEM_BASE_EVENTS": base_bracket,
                    "LOWMEM_DELTA_EVENTS": delta_bracket,
                    "LOWMEM_BUDGET_KB": budget_kb,
                    "LOWMEM_CGROUP_ENFORCE": cgroup_enforce,
                    "LOWMEM_CGROUP_LIMIT_KB": cgroup_limit_kb,
                },
                allow_failure=True,
            )

        if self.env_value("PERF_LOWMEM_RUN_LARGE_TARGET", "0") == "1":
            self.run(
                f"Lowmem Delta ({base_large}+{delta_target} messages, slow opt-in)",
                [str(self.lowmem_script), "delta10k"],
                extra_env={
                    "LOWMEM_BASE_EVENTS": base_large,
                    "LOWMEM_DELTA_EVENTS": delta_target,
                    "LOWMEM_BUDGET_KB": budget_kb,
                    "LOWMEM_CGROUP_ENFORCE": cgroup_enforce,
                    "LOWMEM_CGROUP_LIMIT_KB": cgroup_limit_kb,
                },
                allow_failure=True,
            )

        if self.env_value("PERF_LOWMEM_RUN_FILES", "1") == "1":
            self.run(
                f"Lowmem Delta Files ({file_baseline}+{file_count}x{file_size_mib}MiB)",
                [str(self.lowmem_script), "deltafiles"],
                extra_env={
                    "LOWMEM_BASE_EVENTS": file_baseline,
                    "LOWMEM_DELTA_FILES": file_count,
                    "LOWMEM_DELTA_FILE_MIB": file_size_mib,
                    "LOWMEM_BUDGET_KB": budget_kb,
                    "LOWMEM_CGROUP_ENFORCE": cgroup_enforce,
                    "LOWMEM_CGROUP_LIMIT_KB": cgroup_limit_kb,
                },
                allow_failure=True,
            )

    def run_lowmem_poc(self) -> None:
        if self.env_value("PERF_LOWMEM_POC_ENABLE", "0") != "1":
            return

        budget_kb = self.env_value("PERF_LOWMEM_BUDGET_KB", "24576")
        cgroup_enforce = self.env_value("PERF_LOWMEM_CGROUP_ENFORCE", "1")
        cgroup_limit_kb = self.env_value("PERF_LOWMEM_CGROUP_LIMIT_KB", "22528")

        self.run(
            "Lowmem POC Messages (1M+10k, 24MB gate)",
            [str(self.lowmem_script), "delta10k"],
            extra_env={
                "LOWMEM_BASE_EVENTS": self.env_value("PERF_LOWMEM_POC_MSG_BASELINE", "1000000"),
                "LOWMEM_DELTA_EVENTS": self.env_value("PERF_LOWMEM_POC_MSG_DELTA", "10000"),
                "LOWMEM_BUDGET_KB": budget_kb,
                "LOWMEM_CGROUP_ENFORCE": cgroup_enforce,
                "LOWMEM_CGROUP_LIMIT_KB": cgroup_limit_kb,
            },
            allow_failure=True,
        )

        self.run(
            "Lowmem POC Files Realism (500k+100x1MiB, 24MB gate)",
            [str(self.lowmem_script), "deltafiles"],
            extra_env={
                "LOWMEM_BASE_EVENTS": self.env_value(
                    "PERF_LOWMEM_POC_REALISM_FILE_BASELINE", "500000"
                ),
                "LOWMEM_DELTA_FILES": self.env_value(
                    "PERF_LOWMEM_POC_REALISM_FILE_COUNT", "100"
                ),
                "LOWMEM_DELTA_FILE_MIB": self.env_value(
                    "PERF_LOWMEM_POC_REALISM_FILE_SIZE_MIB", "1"
                ),
                "LOWMEM_BUDGET_KB": budget_kb,
                "LOWMEM_CGROUP_ENFORCE": cgroup_enforce,
                "LOWMEM_CGROUP_LIMIT_KB": cgroup_limit_kb,
            },
            allow_failure=True,
        )

        self.run(
            "Lowmem POC Files Extreme (0+10k x1MiB, 24MB gate)",
            [str(self.lowmem_script), "deltafilesquick"],
            extra_env={
                "LOWMEM_QUICK_DELTA_FILES": self.env_value(
                    "PERF_LOWMEM_POC_FILE_COUNT", "10000"
                ),
                "LOWMEM_QUICK_DELTA_FILE_MIB": self.env_value(
                    "PERF_LOWMEM_POC_FILE_SIZE_MIB", "1"
                ),
                "LOWMEM_QUICK_TIMEOUT_SECS": self.env_value(
                    "PERF_LOWMEM_POC_FILE_TIMEOUT_SECS", "3600"
                ),
                "LOWMEM_BUDGET_KB": budget_kb,
                "LOWMEM_CGROUP_ENFORCE": cgroup_enforce,
                "LOWMEM_CGROUP_LIMIT_KB": cgroup_limit_kb,
            },
            allow_failure=True,
        )

    def ensure_perf_md_markers(self) -> None:
        text = self.perf_md.read_text()
        if "<!-- PERF_AUTO_RESULTS_START -->" in text:
            return
        self.perf_md.write_text(
            text
            + "\n\n## Latest Results\n\n"
            + "This section is updated by `python3 scripts/run_perf_serial.py` when `WRITE_PERF_MD=1`.\n\n"
            + "<!-- PERF_AUTO_RESULTS_START -->\n"
            + "_Not generated yet. Run `python3 scripts/run_perf_serial.py core`._\n"
            + "<!-- PERF_AUTO_RESULTS_END -->\n"
        )

    def replace_perf_md_auto_section(self) -> None:
        self.ensure_perf_md_markers()
        text = self.perf_md.read_text()
        generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        replacement = (
            f"_Generated by `python3 scripts/run_perf_serial.py {self.mode}` on {generated}._\n\n"
            + "".join(self.auto_results)
        ).rstrip()
        new_text = re.sub(
            r"(?ms)^<!-- PERF_AUTO_RESULTS_START -->\n.*?\n<!-- PERF_AUTO_RESULTS_END -->$",
            f"<!-- PERF_AUTO_RESULTS_START -->\n{replacement}\n<!-- PERF_AUTO_RESULTS_END -->",
            text,
        )
        self.perf_md.write_text(new_text)
        print(f"\nUpdated {self.perf_md} auto-results section.")

    def run_mode(self) -> None:
        if self.mode == "core":
            self.run_daemon_perf_test("Core Sync (daemon_perf_test perf_sync_10k)", "perf_sync_10k")
            self.run_daemon_perf_test(
                "Core Sync (daemon_perf_test perf_continuous_10k)",
                "perf_continuous_10k",
            )
            self.run_star_topology(
                "Star Topology (perf_star_topology_capacity, 50 leaves)",
                leaves=50,
                allow_failure=True,
            )
            self.run(
                "File Throughput (file_throughput_test)",
                [
                    "cargo",
                    "+stable",
                    "test",
                    "--release",
                    "--test",
                    "file_throughput_test",
                    "--",
                    "--nocapture",
                    "--test-threads=1",
                ],
            )
            self.run(
                "Topo Cascade (topo_cascade_10k)",
                [
                    "cargo",
                    "+stable",
                    "test",
                    "--release",
                    "--test",
                    "topo_cascade_test",
                    "topo_cascade_10k",
                    "--",
                    "--nocapture",
                    "--test-threads=1",
                ],
            )
            self.run_topo_cascade(
                "topo_cascade_lowmem_10k", extra_env={"LOW_MEM_IOS": "1"},
            )
            return

        if self.mode == "lowmem":
            self.run_lowmem_matrix()
            self.run_lowmem_poc()
            return

        if self.mode == "network":
            self.run_daemon_realistic_network_perf_test(
                "Realistic Network Sync (perf_sync_2k_realistic_profiles)",
                "perf_sync_2k_realistic_profiles",
            )
            self.run_daemon_realistic_network_perf_test(
                "Realistic Network Sync (perf_sync_10k_realistic_profiles)",
                "perf_sync_10k_realistic_profiles",
            )
            self.run_daemon_realistic_network_perf_test(
                "Realistic Network Sync (perf_continuous_10k_realistic_profiles)",
                "perf_continuous_10k_realistic_profiles",
            )
            self.run_daemon_realistic_network_perf_test(
                "Realistic Network Sync (perf_sync_50k_realistic_profiles)",
                "perf_sync_50k_realistic_profiles",
            )
            self.run_daemon_realistic_network_perf_test(
                "Realistic Network Sync (perf_sync_100k_realistic_profiles)",
                "perf_sync_100k_realistic_profiles",
            )
            self.run_daemon_realistic_network_perf_test(
                "Realistic Network Sync (perf_sync_200k_realistic_profiles)",
                "perf_sync_200k_realistic_profiles",
            )
            self.run_daemon_realistic_network_perf_test(
                "Realistic Network Sync (perf_sync_500k_realistic_profiles)",
                "perf_sync_500k_realistic_profiles",
            )
            return

        if self.mode == "full":
            self.run_mode_core_full_common()
            self.run_daemon_perf_test(
                "Core Sync (daemon_perf_test perf_sync_50k, ignored)",
                "perf_sync_50k",
                ignored=True,
                allow_failure=True,
            )
            self.run_topo_cascade("topo_cascade_50k", ignored=True)
            self.run_topo_cascade("topo_cascade_200k", ignored=True)
            self.run_topo_cascade("topo_cascade_500k", ignored=True)
            self.run_low_mem_tests()
            self.run(
                "Large Trust-Set Low-Memory (low_mem_large_trustset_test)",
                [
                    "cargo",
                    "+stable",
                    "test",
                    "--release",
                    "--test",
                    "low_mem_large_trustset_test",
                    "--",
                    "--nocapture",
                    "--test-threads=1",
                ],
            )
            if self.env_value("PERF_LOWMEM_FULL_ENABLE", "1") == "1":
                self.run_lowmem_matrix()
                self.run_lowmem_poc()
            return

        raise SystemExit(
            f"unknown mode: {self.mode}\nusage: python3 scripts/run_perf_serial.py [core|lowmem|network|full]"
        )

    def run_mode_core_full_common(self) -> None:
        self.run_daemon_perf_test("Core Sync (daemon_perf_test perf_sync_10k)", "perf_sync_10k")
        self.run_daemon_perf_test(
            "Core Sync (daemon_perf_test perf_continuous_10k)",
            "perf_continuous_10k",
        )
        self.run(
            "File Throughput (file_throughput_test, include ignored)",
            [
                "cargo",
                "+stable",
                "test",
                "--release",
                "--test",
                "file_throughput_test",
                "--",
                "--nocapture",
                "--include-ignored",
                "--test-threads=1",
            ],
        )
        self.run_delivery_latency_test(
            "Delivery Latency Gate (2 msg/s, 15s, forward-on-have)",
            "perf_two_peer_delivery_latency_gate",
            extra_env={
                "TOPO_PERF_PRELOAD_MESSAGES": "0",
                "TOPO_PERF_MESSAGES_PER_SEC": "2",
                "TOPO_PERF_LIVE_SECONDS": "15",
                "TOPO_PERF_PROGRESS_WINDOWS": "6",
            },
            summary_file="two-peer-gate-pre0-m2-s15-w6.summary",
        )
        self.run_delivery_latency_test(
            "Delivery Latency: forward-on-have only (2 msg/s, 15s)",
            "perf_delivery_forward_only",
            summary_file="two-peer-forward-pre0-m2-s15-w6.summary",
        )
        self.run_delivery_latency_test(
            "Delivery Latency: negentropy only, 5s rounds (2 msg/s, 15s)",
            "perf_delivery_negentropy_only",
            extra_env={"TOPO_FORWARD_ON_HAVE": "0"},
            summary_file="two-peer-negentropy-pre0-m2-s15-w6.summary",
        )
        self.run_delivery_latency_test(
            "Delivery Latency: both, production mode (2 msg/s, 15s)",
            "perf_delivery_both",
            summary_file="two-peer-both-pre0-m2-s15-w6.summary",
        )
        self.run_delivery_latency_test(
            "Delivery Latency (10 msg/s, 20s, forward-on-have)",
            "perf_two_peer_delivery_latency_over_time",
            extra_env={
                "TOPO_PERF_PRELOAD_MESSAGES": "0",
                "TOPO_PERF_MESSAGES_PER_SEC": "10",
                "TOPO_PERF_LIVE_SECONDS": "20",
                "TOPO_PERF_PROGRESS_WINDOWS": "4",
            },
            summary_file="two-peer-pre0-m10-s20-w4.summary",
        )
        self.run(
            "Topo Cascade (topo_cascade_10k)",
            [
                "cargo",
                "+stable",
                "test",
                "--release",
                "--test",
                "topo_cascade_test",
                "topo_cascade_10k",
                "--",
                "--nocapture",
                "--test-threads=1",
            ],
        )
        self.run_topo_cascade(
            "topo_cascade_lowmem_10k", extra_env={"LOW_MEM_IOS": "1"},
        )

    def run_daemon_perf_test(
        self,
        label: str,
        test_name: str,
        ignored: bool = False,
        allow_failure: bool = False,
    ) -> None:
        args = [
            "cargo",
            "+stable",
            "test",
            "--release",
            "--test",
            "daemon_perf_test",
            test_name,
            "--",
            "--nocapture",
        ]
        if ignored:
            args.append("--ignored")
        args.append("--test-threads=1")
        self.run_capture(
            label,
            args,
            allow_failure=allow_failure,
            summary_path=self.repo_root / f"target/perf-results/daemon_perf_test.{test_name}.summary",
        )

    def run_star_topology(
        self,
        label: str,
        leaves: int,
        allow_failure: bool = False,
    ) -> None:
        extra_env = {
            "STAR_TOPOLOGY_LEAVES": str(leaves),
            "STAR_TOPOLOGY_HUB_MESSAGES": "1",
            "STAR_TOPOLOGY_MESSAGES_PER_LEAF": "1",
        }
        args = [
            "cargo",
            "+stable",
            "test",
            "--release",
            "--test",
            "daemon_perf_test",
            "perf_star_topology_capacity",
            "--",
            "--nocapture",
            "--ignored",
            "--test-threads=1",
        ]
        self.run_capture(
            label,
            args,
            extra_env=extra_env,
            allow_failure=allow_failure,
            summary_path=self.repo_root / "target/perf-results/daemon_perf_test.perf_star_topology_capacity.summary",
        )

    def run_daemon_realistic_network_perf_test(
        self,
        label: str,
        test_name: str,
    ) -> None:
        args = [
            "cargo",
            "+stable",
            "test",
            "--release",
            "--test",
            "daemon_realistic_network_perf_test",
            test_name,
            "--",
            "--nocapture",
            "--ignored",
            "--test-threads=1",
        ]
        self.run_capture(
            label,
            args,
            summary_path=(
                self.repo_root
                / f"target/perf-results/daemon_realistic_network_perf_test.{test_name}.summary"
            ),
        )

    def run_delivery_latency_test(
        self,
        label: str,
        test_name: str,
        extra_env: dict[str, str] | None = None,
        summary_file: str | None = None,
    ) -> None:
        args = [
            "cargo",
            "+stable",
            "test",
            "--release",
            "--test",
            "multi_peer_delivery_latency_perf_test",
            test_name,
            "--",
            "--nocapture",
            "--ignored",
            "--test-threads=1",
        ]
        env = extra_env or {}
        env.setdefault("TOPO_FORWARD_ON_HAVE", "1")
        env.setdefault("TOPO_PERF_STAGE_BREAKDOWN", "1")
        summary_path = (
            self.repo_root / f"target/perf-results/{summary_file}"
            if summary_file
            else None
        )
        self.run_capture(label, args, extra_env=env, summary_path=summary_path)

    def run_topo_cascade(
        self, test_name: str, ignored: bool = False, extra_env: dict[str, str] | None = None,
    ) -> None:
        args = [
            "cargo",
            "+stable",
            "test",
            "--release",
            "--test",
            "topo_cascade_test",
            test_name,
            "--",
            "--nocapture",
        ]
        if ignored:
            args.append("--ignored")
        args.append("--test-threads=1")
        self.run(f"Topo Cascade ({test_name})", args, extra_env=extra_env)

    def run_low_mem_tests(self) -> None:
        self.run(
            "Low-Memory (low_mem_ios_functional_smoke_2k)",
            [
                "cargo",
                "+stable",
                "test",
                "--release",
                "--test",
                "low_mem_test",
                "low_mem_ios_functional_smoke_2k",
                "--",
                "--nocapture",
                "--test-threads=1",
            ],
        )
        self.run(
            "Low-Memory (low_mem_ios_budget_smoke_10k, ignored)",
            [
                "cargo",
                "+stable",
                "test",
                "--release",
                "--test",
                "low_mem_test",
                "low_mem_ios_budget_smoke_10k",
                "--",
                "--nocapture",
                "--ignored",
                "--test-threads=1",
            ],
        )


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "core"
    runner = PerfRunner(mode)
    try:
        runner.run_mode()
        if runner.write_perf_md:
            runner.replace_perf_md_auto_section()
    finally:
        runner.tmpdir.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
