from scanner.check_host_network import check_host_network
from scanner.check_privileged_containers import check_privileged_containers
 
def print_findings(title, findings):
    print(f"\n{title}")
    if not findings:
        print("이상 없음")
    else:
        for item in findings:
            line = f"- [{item['namespace']}] {item['pod']}"
            if 'container' in item:
                line += f" (컨테이너: {item['container']})"
            line += f" → {item['reason']}"
            print(line)

def main():
    print("쿠버네티스 보안 설정 점검 시작...\n")

    # 점검 1: hostNetwork 사용 여부
    host_network_findings = check_host_network()
    print_findings("hostNetwork 설정 점검", host_network_findings)

    # 점검 2: privileged 컨테이너 여부
    privileged_findings = check_privileged_containers()
    print_findings("Privileged 컨테이너 점검", privileged_findings)

    print("\n모든 점검 완료.")

if __name__ == "__main__":
    main()

