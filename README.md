# AWS Guardduty Introuduction

## Index

* [Preparation](#preparation)
* [Slack](#slack)
* [Party](#party)
* [More](#more)

# Introduction

* AWS GuardDuty(이하 GD)?
  - VPC 흐름 로그, DNS 로그, CloudTrail 이벤트
  - 쉽게 통합

# Preparation

![Structure](guardduty.png)

6 번은 제외

## Lab 구성

  - `EC2` 에서 [Key Pairs](https://console.aws.amazon.com/ec2/v2/home)에서 `Create Key Pair`를 통해 키쌍의 이름은 `gangnam`으로 정하고 다운로드 받습니다.

  - [Demo CFN template](https://raw.githubusercontent.com/awslabs/amazon-guardduty-tester/master/guardduty-tester.template) 이 파일을 다운로드 받고, `guardduty-tester.template` 로 저장합니다.

  - [Cloudformation Console](https://console.aws.amazon.com/cloudformation/home) 에서 `Create Stack`을 클릭합니다.

  - Select Template
    - `Choose a template` 에서 `Upload a template to Amazon S3`를 체크 후 방금 다운로드 받은 `guardduty-tester.template` 을 선택하고, `Next`를 합니다.

  - Specify Details
    - `Stack Name` 은 `gangnam-GuardDutyTest`로
    - `Availability Zones`을 `ap-northeast-2a` 로 선택
    - `Key Pair Name` 은 `gangnam` 
    - `Allowed Bastion External Access CIDR` 는 그냥 `0.0.0.0/0` 으로 둡니다.
    - `Next` 합니다.

  - Options
    - `Next` 합니다.

  - Review
    - `I acknowledge that AWS CloudFormation might create IAM resources.`에 체크 하시고
    - `Create` 합니다.

  - `CREATE_IN_PROGRESS` 로 바뀌며 10분 후 정도면, 데모를 운영해 볼 수 있는 구성이 준비됩니다.

## Slack 구성

  - 슬랙 준비
    - 슬랙은 별도로 다운 안 받고 브라우저로만 해도 됩니다.
        혹, 슬랙에 가입이 안되어 있으시다면, 슬랙에 가입하시고,
        [AWSKRUG 초청](http://slack.awskr.org)에 가셔서 이메일을 등록하시면 초청 메일 통해서 [AWSKRUG slack](https://awskrug.slack.com)으로 들어오실 수 있습니다.

    - 슬랙 웹 훅 주소 알아야 합니다.
        브라우저로 `AWSKRUG slack`으로 로그인한 다음에 [Slack web hook](https://my.slack.com/services/new/incoming-webhook/) 열어 봅니다.

        - `Add Configuration` 버튼을 클릭합니다.
        - `Post to Channel` 에서 `#guardduty` 를 선택합니다.
        - 그러면 하단에 `Add Incoming WebHooks integration` 이 표시되고, 이 버튼을 클릭하면, `Webhook URL`이 표시됩니다.
        - 요 `Webhook URL` 값을 복사해 둡니다.

  - 슬랙 연결 [CFN template](https://raw.githubusercontent.com/aws-samples/amazon-guardduty-to-slack/master/gd2slack.template) 파일을 다운로드 받고, `gd2slack.template` 으로 저장합니다.

  - [Cloudformation Console](https://console.aws.amazon.com/cloudformation/home) 에서 `Create Stack`을 클릭합니다.

  - Select Template
    - `Choose a template` 에서 `Upload a template to Amazon S3`를 체크 후 방금 다운로드 받은 `gd2slack.template` 을 선택하고, `Next`를 합니다.

  - Specify Details
    - `Slack Incoming Web Hook URL` 은 방금 복사했던, `Webhook URL`을 입력합니다.
    - `Slack channel to send findings to` 는 `#guardduty`이겠지요?
    - `Minimum severity level (LOW, MED, HIGH)` 은 그냥 `LOW` 로 둡니다.
    - `Next` 합니다.

  - Options
    - `Next` 합니다.

  - Review
    - `I acknowledge that AWS CloudFormation might create IAM resources.`에 체크 하시고
    - `Create` 합니다.

  - `CREATE_IN_PROGRESS` 로 바뀌며 2분 후 정도면, 위협이 발생할 떄마다 슬랙에 메시지를 보내줍니다.
    
# Party

* 둘다 `CREATE_COMPLETE`이 될 떄까지 기다립니다.

* 이제 `Compromised Instance`에 접속해서, `./guardduty-tester1.sh` 을 실행해볼까요?
  - Putty 는 https://docs.aws.amazon.com/ko_kr/AWSEC2/latest/UserGuide/putty.html
  - Mac/Linux 는 https://docs.aws.amazon.com/ko_kr/AWSEC2/latest/UserGuide/AccessingInstancesLinux.html

* 이렇게 10 분정도 지나면...

* [Guardduty Console](https://console.aws.amazon.com/guardduty/home)에 들어가 보시면 혹은 Slack 으로 이미 여러 메시지가 와 있을 것입니다.

* 한번 살펴 볼까요?
    ```json
    {
        "Resource": {
            "ResourceType": "Instance", 
            "InstanceDetails": {
                "ProductCodes": [], 
                "AvailabilityZone": "ap-southeast-1c", 
                "Tags": [], 
                "InstanceId": "i-01566173adc7471ae", 
                "InstanceState": "running", 
                "ImageDescription": "Amazon Linux 2 AMI 2.0.20180622.1 x86_64 HVM gp2", 
                "ImageId": "ami-05868579", 
                "LaunchTime": "2018-08-08T02:54:54Z", 
                "InstanceType": "t2.micro", 
                "NetworkInterfaces": [
                    {
                        "VpcId": "vpc-b2f78ed5", 
                        "PrivateIpAddresses": [
                            {
                                "PrivateDnsName": "ip-172-31-5-239.ap-southeast-1.compute.internal", 
                                "PrivateIpAddress": "172.31.5.239"
                            }
                        ], 
                        "NetworkInterfaceId": "eni-00517862bed01b666", 
                        "PublicDnsName": "ec2-13-250-231-26.ap-southeast-1.compute.amazonaws.com", 
                        "PublicIp": "13.250.231.26", 
                        "PrivateDnsName": "ip-172-31-5-239.ap-southeast-1.compute.internal", 
                        "SecurityGroups": [
                            {
                                "GroupName": "launch-wizard-1", 
                                "GroupId": "sg-09970c788c64e53a3"
                            }
                        ], 
                        "Ipv6Addresses": [], 
                        "SubnetId": "subnet-827c92db", 
                        "PrivateIpAddress": "172.31.5.239"
                    }
                ]
            }
        }, 
        "Description": "54.169.40.11 is performing SSH brute force attacks against i-01566173adc7471ae. Brute force attacks are used to gain unauthorized access to your instance by guessing the SSH password.", 
        "Service": {
            "Count": 1, 
            "Archived": true, 
            "ServiceName": "guardduty", 
            "EventFirstSeen": "2018-08-08T05:39:22Z", 
            "ResourceRole": "TARGET", 
            "EventLastSeen": "2018-08-08T05:49:22Z", 
            "DetectorId": "$detector_id", 
            "Action": {
                "ActionType": "NETWORK_CONNECTION", 
                "NetworkConnectionAction": {
                    "ConnectionDirection": "INBOUND", 
                    "Protocol": "TCP", 
                    "RemoteIpDetails": {
                        "GeoLocation": {
                            "Lat": 1.2931, 
                            "Lon": 103.8558
                        }, 
                        "City": {
                            "CityName": "Singapore"
                        }, 
                        "IpAddressV4": "54.169.40.11", 
                        "Organization": {
                            "Org": "Amazon", 
                            "Isp": "Amazon", 
                            "Asn": "16509", 
                            "AsnOrg": "Amazon.com, Inc."
                        }, 
                        "Country": {
                            "CountryName": "Singapore"
                        }
                    }, 
                    "RemotePortDetails": {
                        "PortName": "Unknown", 
                        "Port": 34764
                    }, 
                    "LocalPortDetails": {
                        "PortName": "SSH", 
                        "Port": 22
                    }, 
                    "Blocked": false
                }
            }
        }, 
        "Title": "54.169.40.11 is performing SSH brute force attacks against i-01566173adc7471ae. ", 
        "Type": "UnauthorizedAccess:EC2/SSHBruteForce", 
        "Region": "ap-southeast-1", 
        "Partition": "aws", 
        "Arn": "arn:aws:guardduty:ap-southeast-1:691767955026:detector/$detector_id/finding/aab28c0b70217e0cf7915738e79f4a7f", 
        "UpdatedAt": "2018-08-08T05:51:17.058Z", 
        "SchemaVersion": "2.0", 
        "Severity": 2, 
        "Id": "aab28c0b70217e0cf7915738e79f4a7f", 
        "CreatedAt": "2018-08-08T05:51:17.058Z", 
        "AccountId": "691767955026"
    }
    ```

* 수행하는 공격들?
    1) UnauthorizedAccess:EC2/SSHBruteForce
    EC2 인스턴스가 SSH 무차별 암호 대입 공격에 관여
    이 조사 결과는 AWS 환경의 EC2인스턴스가 Linux 기반 시스템의 SSH 서비스에 대한 암호를 얻기 위한 목적으로 행해진 무차별 암호 대입 공격에 관여했을을 알려 줍니다.
    
    2) UnauthorizedAccess:EC2/RDPBruteForce
    EC2 인스턴스가 RDP 무차별 암호 대입 공격에 관여했습니다.
    이 조사 결과는 AWS 환경의 EC2 인스턴스가 Windows 기반 시스템의 RDP 서비스에 대한 암호를 얻기 위한 목적으로 행해진 무차별 암호 대입 공격에 관여했음을 알려 줍니다. 이는 AWS 리소스에 대한 무단 액세스를 나타낼 수 있습니다.
    
    3) CryptoCurrency:EC2/BitcoinTool.B!DNS
    EC2 인스턴스가 비트코인 마이닝 풀과 통신
    이 조사 결과는 AWS 환경의 EC2 인스턴스가 비트코인 마이닝 풀과 통신함을 알려 줍니다. 암호 화폐 마이닝 분야에서 마이닝 도구는 블록 해결에 기여한 작업량에 따라 보상을 분할하기 위해 네트워크를 통해 처리 능력을 공유하는 마이너별 리소스 풀링입니다.
    
    4) Trojan:EC2/DNSDataExfiltration
    EC2 인스턴스가 DNS 쿼리를 통해 데이터를 유출
    이 조사 결과는 AWS 환경에 아웃바운드 데이터 전송에 DNS 쿼리를 사용하는 맬웨어가 있는 EC2 인스턴스가 있음을 알려 줍니다. 그 결과, 데이터가 유출됩니다. 이 EC2 인스턴스는 손상되었을 수 있습니다. DNS 트래픽은 일반적으로 방화벽으로 차단되지 않습니다. 예를 들어, 손상된 EC2 인스턴스에 있는 맬웨어는 데이터(예: 신용카드 번호)를 DNS 쿼리로 인코딩해 공격자가 제어하는 원격 DNS 서버로 전송할 수 있습니다.
    
    5) UnauthorizedAccess:EC2/MaliciousIPCaller.Custom
    사용자 지정 위협 목록의 IP 주소에서 호출
    이 조사 결과는 업로드한 위협 목록에 포함된 IP 주소에서 API 작업(예: EC2 인스턴스를 시작, 새 IAM 사용자를 생성 또는 AWS 권한을 수정하려는 시도 등)이 호출되었음을 알려 줍니다. In GuardDuty에서 위협 목록은 알려진 악성 IP 주소로 이루어져 있습니다. GuardDuty는 업로드된 위협 목록을 기준으로 결과를 작성합니다. 이는 공격자의 실제 신원을 숨기려는 의도를 갖고 AWS 리소스에 무단으로 액세스하려 함을 나타낼 수 있습니다.


# More?

 Q. 멀티 계정은 어떻게?
 - https://github.com/aws-samples/amazon-guardduty-multiaccount-scripts

 Q. 너무 자주 와요? 
 - cloudwatch 에서 severity 를 조절하거나 filter 에서 archiving 하도록 처리하세요.

 Q. 초기 대응도 자동으로 하고 싶어요?
 - 서드 파티 솔루션도 많고
 - https://github.com/dpigliavento/aws-support-tools/tree/master/GuardDuty
 - http://woowabros.github.io/security/2018/02/23/aws-auto-security1.html

 Q. 공격 당한 후에는 어떻게?
 - [Amazon EC2 모범 사례](https://docs.aws.amazon.com/ko_kr/AWSEC2/latest/UserGuide/ec2-best-practices.html)를 참고하세요.

 Q. 아직은 초기버전 아닌가요?
 - 여러 서드파티들을 대동해서...

 Q. 넘 느리지 않나요?
 - 오진보단...

 Q. 시각화는 어떻게?
 - geometry 정보도 있고, 시각화 할 수 있는 정보가 많이 있으니 `Glue` 와 `ELK` 혹은 `QuickSight` 를 적절히 사용하시면 되겠습니다~

