# Intelligent Incident Response Platform

## Index
### Install
  > [HOST PC](#host-pc)
  > [Windows](#Windows-7-32bit)
  > [Ubuntu](#ubuntu-1804-64bit)
### 실행방법
  > [HOST PC](#host-pc)
### Config 설정


##  목표 구성도 참고 
* Open Source Endpoint monitoring 
  - https://github.com/DearBytes/Opensource-Endpoint-Monitoring

##  시스템 구성도 

   ![screenshot](Conceptual_diagram.jpg)

##  환경 구성 
* Windows 7 32bit (Endpoint 환경) - VM 구성
  - Python 2.7 32bit
  - Elastic Winlogbeat 7.6.2
  - sysmon
    > microsoft의 sysinternals.com
  - Red Team Automation (Red Team용 MITRE ATT@CK 기반 malicious attack 발생)
    > https://github.com/endgameinc/RTA
  - SwiftOnSecurity의 sysmon-config (보안로그 발생을 위한 sysmon 환경 파일)
    > https://github.com/SwiftOnSecurity/sysmon-config

## INSTALL
### HOST PC(#index)
* Elastic Stack
  - Elastic Elasticsearch 설치 ( 본 글은 7.11.2 version 사용. )
    > https://www.elastic.co/kr/downloads/past-releases#elasticsearch

  - Elastic Kibana 설치 ( 본 글은 7.11.2 version 사용.) # elasticsearch와 동일 버전을 사용하는 것이 좋음.
    > https://www.elastic.co/kr/downloads/kibana

  - Elastic Logstash (Optional) 설치
    > https://www.elastic.co/kr/downloads/logstash
   
### Windows 7 32bit(VM)(#index)

### Ubuntu 18.04 64bit(VM)(#index)
  - python 설치
  - elasticsearch 설치

  - Yelp의 elastalert
    > https://github.com/Yelp/elastalert

  - elastalert 설치
    > https://elastalert.readthedocs.io/en/latest/running_elastalert.html

## How To Run
### HOST PC
* ElasticSearch // bin/elasticsearch.bat 실행 (관리자 계정)

* Kibana // bin/kibana.bat 실행 (관리자 계정)

### Win7sp1 32bit
* Win7sp1 sysmon vm 환경 실행

* Win7sp1 sysmon vm 환경에서 sysmon 서비스 실행(관리자 계정)
  > sysmon.exe -i %configfile%
    (기존에 설치했다면 필요 없음)

* Win7sp1 sysmon vm 환경에서 winlogbeat 실행(관리자 계정)
  > winlogbeat.exe -c winlogbeat.yml

### Ubuntu 18.04 64bit
* Ubuntu 18.04 64bit 환경에서 Elasticalert 실행
  >/elastalert  
  >python3 -m elastalert.elastalert --verbose --start  --config <config.yaml> --rule <error.yaml>
 
## 메뉴얼 

* sysmon
  > https://github.com/trustedsec/SysmonCommunityGuide/blob/master/Sysmon.md

* elastic
  > https://www.elastic.co/guide/en/elastic-stack-get-started/7.6/get-started-elastic-stack.html#install-elasticsearch

* elastalert
  > https://elastalert.readthedocs.io/en/latest/running_elastalert.html
  
 ## 오류 수정 
 [[ windows 7 ]]
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
        
[[ Elasticsearch ]] 
* network.host 설정 bootstrap checks failed
  > https://soye0n.tistory.com/178


[[ Elastalert ]]
* pip install 오류
  > python version 3.6 다운
  > python으로 실행 안될 시 pip 오류 설정 확인 후 python3 버전으로 설치
  > python3 으로 실행해본 후 여전히 안될 시 기본으로 설정된 python의 버전 설정을 바꾼다.
## Contributors
* maxup37
* idk3669
* air83
