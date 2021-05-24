# Intelligent Incident Response Platform

## INDEX
### Install
  - [HOST PC](#host-pc)
  - [Windows](#Win7sp1-32bitvm)
  - [Ubuntu](#ubuntu-1804-64bitvm)
### 실행방법
  - [HOST PC](#host-pc-1)
  - [Windows](#win7sp1-32bitvm-1)
  - [Ubuntu](#ubuntu-1804-64bitvm-1)
### Config 설정
  - [ElasticSearch](#elasticsearch)
  - [Kibana](#kibana)
  - [Winlogbeat](#winlogbeat)
  - [Elastalert](#elastalert)
  - [Slack](#slack)
  - [Sigma](#sigma)
### [TroubleShooting](#troubleshooting-1)

##  목표 구성도 참고 
* Open Source Endpoint monitoring 
  - https://github.com/DearBytes/Opensource-Endpoint-Monitoring

##  시스템 구성도 

   ![screenshot](Conceptual_diagram.jpg)

##  환경 구성 
* Host PC
  - ElasticSearch 7.11.2
  - Kibana 7.11.2
  - Logstash (optional)
  
* Windows 7 32bit (Endpoint 환경) - VM 구성
  - Python 2.7 32bit
  - Winlogbeat 7.11.2
  - sysmon
  - Red Team Automation (Red Team용 MITRE ATT@CK 기반 malicious attack 발생)
  - SwiftOnSecurity의 sysmon-config (보안로그 발생을 위한 sysmon 환경 파일)
  
* Ubuntu 18.04 64bit - VM
  - Elastalert 0.2.4 version (git clone 사용)
  - python3 
  - pip3
  
## INSTALL
### [HOST PC](#index)
* Elastic Stack
  - Elastic Elasticsearch 설치 ( 본 글은 7.11.2 version 사용. )
    > https://www.elastic.co/kr/downloads/past-releases#elasticsearch

  - Elastic Kibana 설치 ( 본 글은 7.11.2 version 사용.) # elasticsearch와 동일 버전을 사용하는 것이 좋음.
    > https://www.elastic.co/kr/downloads/kibana

  - Elastic Logstash (Optional) 설치
    > https://www.elastic.co/kr/downloads/logstash
   
### [Win7sp1 32bit](#index)(VM)
  - python 2.7 version 32bit
    > https://www.python.org/download/releases/2.7/

  - Red Team Automation (Red Team용 MITRE ATT@CK 기반 malicious attack 발생)
    > https://github.com/endgameinc/RTA 
    > (현 github 내 red_ttp_ko를 다운로드 해도 됨.)
 
  - SwiftOnSecurity의 sysmon-config (보안로그 발생을 위한 sysmon 환경 파일)
    > https://github.com/SwiftOnSecurity/sysmon-config 
    > (현 github 내 sysmon-config.xml을 다운로드 해도 됨.)
    
  - Winlogbeat 7.11.2 version
    > https://www.elastic.co/kr/downloads/past-releases#winlogbeat
    
  - Sysmon 13.10 version
    > https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

### [Ubuntu 18.04 64bit](#index)(VM)
  - python 3.6 version 설치
    > apt install python3 <br>
    > sudo apt install python3-pip

  - elastalert 설치
    > https://elastalert.readthedocs.io/en/latest/running_elastalert.html <br>
    > 본 github 과정은 매뉴얼 내 pip3 install이 아닌 git clone을 통해 설치

## How To Run
### [HOST PC](#index)
* ElasticSearch // bin/elasticsearch.bat 실행 (관리자 계정)

* Kibana // bin/kibana.bat 실행 (관리자 계정)

### [Win7sp1 32bit](#index)(VM)
* Win7sp1 sysmon vm 환경에서 sysmon 서비스 실행(관리자 계정)
  > sysmon.exe -i %configfile%
    (기존에 설치했다면 필요 없음)

* Win7sp1 sysmon vm 환경에서 winlogbeat 실행(관리자 계정)
  > winlogbeat.exe -c winlogbeat.yml
  > 첫 설치 후 서비스에 실행되어 있으면 생략 가능

### [Ubuntu 18.04 64bit](#index)(VM)
* Ubuntu 18.04 64bit 환경에서 Elasticalert 실행
  >/elastalert  <br>
  >python3 -m elastalert.elastalert --verbose --config <config.yaml> // (config.yaml 파일 내 rules_folder: <설정된폴더> 를 따라 룰 파일을 땡겨와 실행한다. 여러 룰 파일을 사용하고 싶으면 이 명령어를 사용한다. 본 매뉴얼을 처음 따라온다면 아래 명령어를 통해 따라한다.) <br>
  >python3 -m elastalert.elastalert --verbose --start  --config <config.yaml> --rule <예제파일>  <br> // 특정 <예제파일>. 이 룰 파일만 설정해 실행한다. 
  > <config.yaml> 에 들어갈 설정 파일은 본 github 내 config.yaml 파일을 수정해서 사용한다. <br>
  > <예제파일>에 들어갈 룰 파일은 https://github.com/Yelp/elastalert/blob/master/example_rules/example_frequency.yaml 을 사용한다. (본 github 내 example_frequency.yaml을 사용해도 됨.)
 
## 메뉴얼 

* sysmon
  > https://github.com/trustedsec/SysmonCommunityGuide/blob/master/Sysmon.md

* elastic
  > https://www.elastic.co/guide/en/elastic-stack-get-started/7.6/get-started-elastic-stack.html#install-elasticsearch

* elastalert
  > https://elastalert.readthedocs.io/en/latest/running_elastalert.html <br>
  > rule 기본 틀 : https://github.com/Yelp/elastalert/blob/master/example_rules/example_frequency.yaml 

## Config
* 기본적으로 맨 앞에 #은 주석이므로 그 라인을 사용하려면 제거해야함. 
* [] <- 이 괄호 내에 한글이 있으면 예시이므로 괄호 포함해서 걸러보면 되며, 영어가 포함되어있으면 괄호도 포함해서 설정한다.
* ex.) [호스트 PC IP] -> 192.0.0.1  ,  [host pc ip] -> [192.0.0.1]  
### [ElasticSearch](#index)
  * HOST PC
  > 설치폴더\config\elasticsearch.yml <br>
  > #------ Network ----- <br>
  > network.host: <host pc IP> <br>
  > 포트는 기본적으로 설정되어있는 9200 사용할 예정이므로 주석제거 안함. <br>
  > #------ Discovery ----- <br>
  > discovery.seed_hosts: ["127.0.0.1, "[::1]"] 
### [Kibana](#index)
  * HOST PC
  > 설치폴더\config\kibana.yml <br>
  > #server.port: 5601  (기본으로 설정되어있는 포트며 변경하지 않는다.) <br>
  > server.host: "host pc ip"  // 키바나를 실행한 PC의 IP를 설정해 준다. <br>
  > elasticsearch.hosts: ["http://[elasticsearch를 실행한 PC IP]:[포트]"] // elasticsearch를 실행할 호스트 PC의 IP를 설정해 준다. <br>
### [Winlogbeat](#index)
  * Win7sp VM
  > #-------- Elasticsearch Output ----- <br>
  > hosts: ["HOST PC IP:PORT"] <br>
  > 이미 winlogbeat 서비스가 실행되고 있을 때 변경해줬다면 서비스를 다시 시작하면 되며, 아니라면 설치 진행 <br>
### [Elastalert](#index)
  * Ubuntu 18.04 VM
  > git clone해서 나온 elastalert 디렉토리 내/config.yaml  // config.yaml이 없다면 config.yaml.example이 있을텐데, 복사 후 뒤에 .example을 지우고 사용한다.<br>
  > es_host: [호스트 PC IP] <br>
  > rules_folder: rule이 들어간 디렉토리 지정 <br>
  > --rule 속성을 사용한다면 룰 파일 하나를 정해주지만, --rule 속성을 주지않으면 이 rules_folder에 정해진 디렉토리가 기본으로 지정되어 디렉토리 내 룰들을 로드한다. <br>
  * rule 파일 결과를 로그로 내보내기
	> rule 하나를 선택 ( 본 과정에서는 example_frequency 사용 ) <br>
	> pipe_match_json: true <br>
	> command: "tee -a [정해줄 디렉토리경로]/[파일이름]-$(date '+%%d-%%m-%%Y').log" // 맨 아래에 입력 <br>
	> 결과는 다음과 같이 나온다 -> [파일이름]-18-05-2021.log // 뒤 날짜는 로그가 잡히는 날짜마다 바뀐다. 
### [Slack](#index)
  * Slack 설치 -> https://slack.com/intl/ko-kr/downloads/windows
  * Slack App생성 -> https://api.slack.com/apps?
	> 사용하는 E메일 입력 후 메일 받아서 로그인. <br>
	> 워크스페이스를 새로 만든다. <br>
	> -- Incoming WebHook 설정 -- <br>
	> 방법1 // https://XXXXX(만든 워크스페이스의 이름).slack.com/services/new/incoming-webhook 접속 <br>
	> 방법2 // Slack 프로그램 내 새로만든 워크스테이션에서 Slack 찾아보기 -> 앱 -> Webhook 검색 후 구성, 추가 <br>
	> 메시지를 표시 할 채널을 선택 (ex #(만든채널) 앞에 #이 아니고 자물쇠 모양이래도 상관없음.) <br>
	> 설정이 된다면 webhook URL이 표시될 것이다. <br>
	> ubuntuVM을 실행, elastalert rule디렉토리로 들어가 임의로 실행할 룰 파일을 하나 고른다. ( 본 과정에서는 example_frequency 사용 ) <br>
	> 아래 양식에 맞춰 룰 파일 내 맨 아래 줄에 입력한다. <br>
	> alert: 	<br>
	> &#45; slack: <br>
        	slack_webhook_url: "(복사한 웹후크 URL)" <br>
        	slack_username_override: "ZEUS" <br>
         	slack_channel_override: "#monitoring" <br>
         	slack_emoji_override: ":,zap,:"   <- , 제거해서 입력 <br>
         	slack_msg_color: "danger" <br>
		
	> 실행 // elastalert --verbose --config config.yaml --rule example_rules/example_frequency <br> 
	> 설정된 룰에 따라 Alert을 발생시키면 Slack에 메시지가 뜨게 된다. <br>
### [Sigma](#index)
  > sudo pip3 install sigmatools <br>
  > git clone https://github.com/Neo23x0/sigma.git <br>
  > cd [시그마폴더](이하 sigma) <br> 
  > cp -r rules/windows [복사를 원하는 경로] // 폴더 째로 복사해서 사본으로 룰을 제작할 예정. <br>
  > sudo sigmac -t elastalert -r -c winlogbeat [위에서 복사한 경로] -o [원하는경로]/[설정할 파일이름] <br>
  > -t 옵션 : elastalert을 타겟으로 설정 <br>
  > -c 옵션 : winlogbeat 인덱스로 설정 <br>
  > -o 옵션 : 원하는 파일 이름으로 설정되어서 나옴. <br>
  > -r 옵션 : 디렉토리 내 서브디렉토리까지 전부. <br>
  > 설정된 파일 하나에 룰 전부가 들어가 저장될 것인데, 여기서 룰 파일은 파일 내 여러 룰을 인식하지 못하고 마지막만 인식하기 때문에 나눠줘야 함. <br>
  > csplit --prefix sigma_ --suffix-format "%04d.yml" rule "/^alert:/" "{*}" (sigmac 명령어를 통해 나온 파일이 있는 폴더에서 해야하며, 많은 파일이 나올 예정.) <br>
  > sigma_0000.yml 파일로 여러개가 저장될 텐데, 전부 elastalert 내 rule 폴더에 넣어준다. <br>
  > 
 
## [TroubleShooting](#index)
 ### [[ windows 7 ]]
 * sysmon 10.x 실행 오류
   > kb2533623 설치 (wevtapi.dll 문제)
   
   > kb3033929 설치

* sysmon-config.xml

  **변경전** 
     
    > \<PipeEvent onmatch="exclude"\>
	
    > \<EVENTID condition="is"\>1\</EVENTID\> 
     
    > \<\/PipeEvent\>
          
   **변경후**   
   
     > \<PipeEvent onmatch="include"\>
			
     >**삭제**
	
     > \</PipeEvent\>
          
   **변경전**
   
     > \<WmiEvent onmatch="include"\>
		
     >    \<Operation condition="is">Created</Operation\> 
            
     > \</WmiEvent\>
           
   **변경후**     
   
     > \<WmiEvent onmatch="include"\>
	
     > **삭제** 
	
     > \</WmiEvent\>
     > 

* Winlogbeat
  > config 설정 후 kibana에 Sysmon 로그가 안뜸 <br>
  > = 서비스에 들어가 winlogbeat 서비스를 다시 시작합니다.
        
### [[ Elasticsearch ]] 
* network.host 설정 bootstrap checks failed
  > https://soye0n.tistory.com/178

### [[ Ubuntu ]] 
* pip install 오류
  > python version 3.6 다운 <br>
  > python으로 실행 안될 시 pip 오류 설정 확인 후 python3 버전으로 설치 <br>
  > python3 으로 실행해본 후 여전히 안될 시 기본으로 설정된 python의 버전 설정을 바꾼다. <br>
 
* urllib3 (1.25.2) or chardet (3.0.4) 오류
  > pip3 install request 
  
* module 'yaml' has no attribute 'FullLoader' 오류
  > pip3 install -U PyYAML 
 
* pkg_resources.DistributionNotFound: The 'elasticsearch' distribution was not found and is required by elastalert 오류
  > sudo pip3 install "elasticsearch>=5.0.0,<7.0.0"
  
* ImportError: cannot import name main
  > pip3 install "elasticsearch>=5.0.0,<7.0.0"


## Contributors
* maxup37
* idk3669
* air83
