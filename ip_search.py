#!/usr/bin/env python3
"""Show how surface_scan.py resolves target hostnames to IP addresses."""

from __future__ import annotations

import argparse
import socket
import sys
from pathlib import Path
from urllib.parse import urlsplit


def extract_hostname(target: str) -> str:
    """Extract a hostname using the same URL assumptions as surface_scan.py."""
    value = target.strip()
    if not value:
        raise ValueError("빈 대상")
    if any(char.isspace() for char in value):
        raise ValueError(f"공백이 포함된 대상: {target}")

    if "://" in value:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError(f"지원하지 않는 URL 스킴: {parsed.scheme}")
    else:
        parsed = urlsplit("https://" + value)

    if not parsed.hostname:
        raise ValueError(f"호스트명을 추출할 수 없음: {target}")
    return parsed.hostname


def family_name(family: int) -> str:
    if family == socket.AF_INET:
        return "IPv4"
    if family == socket.AF_INET6:
        return "IPv6"
    return f"기타({family})"


def resolve(hostname: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Resolve a host exactly like surface_scan.py and preserve resolver order."""
    records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    resolved: list[tuple[str, str]] = []
    unique: list[str] = []

    for family, _socktype, _protocol, _canonical, sockaddr in records:
        address = sockaddr[0]
        resolved.append((family_name(family), address))
        if address not in unique:
            unique.append(address)

    return resolved, unique


def read_targets(arguments: list[str], target_file: Path | None) -> list[str]:
    targets = list(arguments)
    if target_file is not None:
        targets.extend(
            line.strip()
            for line in target_file.read_text(encoding="utf-8-sig").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
    return list(dict.fromkeys(targets))


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        description="HTTP 요청 없이 surface_scan.py와 같은 방식으로 도메인의 IP를 조회합니다."
    )
    parser.add_argument("targets", nargs="*", metavar="TARGET", help="URL 또는 도메인")
    parser.add_argument("-f", "--file", type=Path, metavar="FILE", help="대상 목록 파일")
    parser.add_argument(
        "--raw", action="store_true", help="getaddrinfo가 반환한 중복 포함 레코드도 출력"
    )
    args = parser.parse_args(argv)

    try:
        targets = read_targets(args.targets, args.file)
    except OSError as exc:
        parser.error(f"대상 파일 읽기 실패: {exc}")
    if not targets:
        parser.error("TARGET 또는 -f FILE이 필요합니다")

    failures = 0
    for number, target in enumerate(targets, 1):
        print(f"[{number}/{len(targets)}] 입력: {target}")
        try:
            hostname = extract_hostname(target)
            records, unique = resolve(hostname)
        except (ValueError, OSError) as exc:
            failures += 1
            print(f"  결과: 조회 실패 ({exc})")
            print()
            continue

        ipv4 = [address for address in unique if ":" not in address]
        ipv6 = [address for address in unique if ":" in address]
        print(f"  호스트명: {hostname}")
        print("  조회 방식: socket.getaddrinfo(hostname, None, type=SOCK_STREAM)")
        print(f"  IPv4: {', '.join(ipv4) or '-'}")
        print(f"  IPv6: {', '.join(ipv6) or '-'}")
        print(f"  스캐너 저장값: {', '.join(unique) or '-'}")
        if args.raw:
            print("  원본 반환 순서:")
            for index, (family, address) in enumerate(records, 1):
                print(f"    {index}. {family}: {address}")
        print()

    print(f"완료: 전체 {len(targets)}개 | 성공 {len(targets) - failures}개 | 실패 {failures}개")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
