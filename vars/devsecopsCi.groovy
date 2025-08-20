#!/usr/bin/env groovy

def call(Map cfg = [:]) {
  // ===== Config (with sensible defaults) =====
  def gitUrl            = cfg.gitUrl ?: 'https://github.com/Wrianzz/vulncode.git'
  def dd                = cfg.dd ?: [:]
  def ddProduct         = dd.productName    ?: 'DevSecOps'
  def ddEngagementHint  = dd.engagementName ?: 'Vulnerable-Code'
  def ddUrl             = dd.url            ?: 'http://localhost:8280'
  def ddCredsId         = dd.credsId        ?: 'defectdojo-api-key'
  def sourceCodeUrl     = dd.sourceCodeUrl  ?: gitUrl

  def dockerCfg         = cfg.docker ?: [:]
  def imageNameBase     = dockerCfg.imageNameBase ?: 'my-app'

  def sonar             = cfg.sonar ?: [:]
  def sonarProjectKey   = sonar.projectKey   ?: 'project-key'
  def sonarHostUrl      = sonar.hostUrl      ?: 'http://localhost:9000'
  def sonarScannerTool  = sonar.scannerTool  ?: 'sonarqube'
  def sonarTokenCredsId = sonar.tokenCredsId ?: 'sonarqube-token'

  def mainBranches      = (cfg.mainBranches ?: ['master','main','production']) as List
  def verifiedPolicy    = cfg.verifiedPolicy ?: [
    'Trufflehog Scan': true,
    'Anchore Grype'  : false,
    'Trivy Scan'     : false,
    'SonarQube Scan' : false
  ]

  pipeline {
    agent any

    environment {
      gitUrl               = "${gitUrl}"
      DD_PRODUCT_NAME      = "${ddProduct}"
      DD_ENGAGEMENT_HINT   = "${ddEngagementHint}"
      SOURCE_CODE_URL      = "${sourceCodeUrl}"
      DD_URL               = "${ddUrl}"
      IMAGE_NAME_BASE      = "${imageNameBase}"

      SONAR_PROJECT_KEY    = "${sonarProjectKey}"
      SONAR_HOST_URL       = "${sonarHostUrl}"
      SONAR_SCANNER        = tool "${sonarScannerTool}"
    }

    parameters {
      string(name: 'COMMIT_HASH', defaultValue: '', description: 'Commit Message/Hash for build (default: auto)')
      string(name: 'BRANCHNAME_PARAM', defaultValue: '', description: 'Branch name for manual build (empty = auto)')
    }

    stages {
      stage('Init') {
        steps {
          script {
            echo "🚀 Starting build number: ${env.BUILD_NUMBER}"
            if (!params.COMMIT_HASH?.trim()) {
              env.COMMIT_HASH = sh(script: 'git rev-parse HEAD', returnStdout: true).trim()
            } else {
              env.COMMIT_HASH = params.COMMIT_HASH
            }
            echo "🔖 Commit hash/message for this build: ${env.COMMIT_HASH}"
          }
        }
      }

      stage('Checkout') {
        steps {
          script {
            def isManual = params.BRANCHNAME_PARAM?.trim()
            if (isManual) {
              env.branch_name = params.BRANCHNAME_PARAM
            } else {
              env.branch_name = env.GIT_BRANCH?.replaceAll('origin/', '') ?: 'main'
            }

            cleanWs()
            git branch: env.branch_name, url: env.gitUrl
            env.imageTag = env.BUILD_NUMBER

            // Dynamic sanitized engagement name: <product>-<branch>
            env.engagement_name = "${env.DD_PRODUCT_NAME}-${env.branch_name}".replaceAll(/[^A-Za-z0-9._-]/, '-')
            echo "🧩 Dynamic Engagement: ${env.engagement_name}"
          }
        }
      }

      stage('Test (Security)') {
        parallel {
          stage('Secrets Scan (TruffleHog)') {
            steps {
              script {
                def rc = sh(script: 'trufflehog filesystem . --json > trufflehog-report.json', returnStatus: true)
                sh 'cat trufflehog-report.json || echo "Report kosong atau tidak terbaca"'
                if (mainBranches.contains(env.branch_name) && rc != 0) {
                  echo "Secret ditemukan oleh TruffleHog di branch ${env.branch_name}. Pipeline bypassed."
                } else {
                  echo "Secret scanning selesai. ${mainBranches.contains(env.branch_name) ? 'Blocking on any secret (bypassed).' : 'Continuing despite findings.'}"
                }
                archiveArtifacts artifacts: 'trufflehog-report.json', fingerprint: true
              }
            }
          }

          stage('SCA (Grype)') {
            steps {
              script {
                sh '''
                  docker run --rm -v "$(pwd)":/src -w /src anchore/grype:latest \
                  dir:/src -o json > grype-report.json || true
                '''
                archiveArtifacts artifacts: 'grype-report.json', fingerprint: true
              }
            }
          }
        }
      }

      stage('Build Image') {
        steps {
          script {
            sh 'docker build --network=host -t ${IMAGE_NAME_BASE}:${imageTag} .'
          }
        }
      }

      stage('Image Scan (Trivy)') {
        steps {
          script {
            def strict = mainBranches.contains(env.branch_name)
            def trivyArgs = strict ? '--severity HIGH,CRITICAL --exit-code 1' : ''
            def rc = sh(script: '''
              docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest \
              image ${trivyArgs} --format json ${IMAGE_NAME_BASE}:${imageTag} > trivy-report.json || true
            ''', returnStatus: true)
            archiveArtifacts artifacts: 'trivy-report.json', fingerprint: true
            if (strict && rc != 0) {
              error 'Critical vulnerabilities found in main/protected branch image!'
            }
          }
        }
      }

      stage('SAST (SonarQube)') {
        steps {
          withCredentials([string(credentialsId: sonarTokenCredsId, variable: 'SONAR_TOKEN')]) {
            withSonarQubeEnv("${env.SONAR_ENV}") {
              script {
                sh '''
                  ${SONAR_SCANNER}/bin/sonar-scanner \
                    -Dsonar.projectKey=${SONAR_PROJECT_KEY} \
                    -Dsonar.sources=. \
                    -Dsonar.token=${SONAR_TOKEN} \
                  | tee sonarqube_out.txt
                '''

                env.sonarTaskID = sh(
                  script: "grep -o 'id=[a-f0-9-]\\+' sonarqube_out.txt | cut -d= -f2 | head -n1",
                  returnStdout: true
                ).trim()
                echo "SonarQube Task ID: ${env.sonarTaskID}"

                def taskStatus = ''
                def maxWait = 120 // seconds
                def waited = 0
                while (waited < maxWait) {
                  def response = sh(
                    script: '''curl -s -u "${SONAR_TOKEN}:" "${SONAR_HOST_URL}/api/ce/task?id=${sonarTaskID}"''',
                    returnStdout: true
                  )
                  taskStatus = sh(script: "echo '${response}' | jq -r '.task.status'", returnStdout: true).trim()
                  if (taskStatus in ['SUCCESS','FAILED','CANCELED']) {
                    env.analysisId = sh(script: "echo '${response}' | jq -r '.task.analysisId'", returnStdout: true).trim()
                    break
                  }
                  sleep 3
                  waited += 3
                }
                echo "Task Status: ${taskStatus}"
                echo "SonarQube Analysis ID: ${env.analysisId}"

                sh '''
                  curl -s -u "${SONAR_TOKEN}:" \
                    "${SONAR_HOST_URL}/api/hotspots/search?project=${SONAR_PROJECT_KEY}" \
                    -o sonarqube-scan-report.json
                '''
                archiveArtifacts artifacts: 'sonarqube-scan-report.json', fingerprint: true
              }
            }
          }
        }
      }

      stage('Publish to DefectDojo') {
        steps {
          script {
            def uploads = [
              [file: 'trufflehog-report.json',     scanType: 'Trufflehog Scan'],
              [file: 'grype-report.json',          scanType: 'Anchore Grype'],
              [file: 'trivy-report.json',          scanType: 'Trivy Scan'],
              [file: 'sonarqube-scan-report.json', scanType: 'SonarQube Scan']
            ]

            withCredentials([string(credentialsId: ddCredsId, variable: 'DD_API_KEY')]) {
              // Check if engagement exists for product+name
              def engagementCount = sh(
                script: '''
                  curl -s -G "${DD_URL}/api/v2/engagements/" \
                    -H "Authorization: Token ${DD_API_KEY}" \
                    --data-urlencode "name=${engagement_name}" \
                    --data-urlencode "product__name=${DD_PRODUCT_NAME}" | jq -r '.count'
                ''', returnStdout: true
              ).trim()

              def dateFields = ''
              if (engagementCount == '0') {
                def startDate = java.time.LocalDate.now().toString()
                def endDate   = java.time.LocalDate.now().plusDays(180).toString()
                dateFields = "-F engagement_start_date=${startDate} -F engagement_end_date=${endDate}"
                echo "🆕 First-time engagement '${env.engagement_name}' → set dates ${startDate}..${endDate}"
              } else {
                echo "↔️ Engagement '${env.engagement_name}' already exists → skip date fields."
              }

              uploads.each { u ->
                if (fileExists(u.file)) {
                  def verifiedFlag = verifiedPolicy.get(u.scanType, false) ? 'true' : 'false'
                  echo "📤 Reimport ${u.file} → DefectDojo (${u.scanType})"
                  sh """
                    curl -sS -X POST "${DD_URL}/api/v2/reimport-scan/" \
                      -H "Authorization: Token ${DD_API_KEY}" \
                      -F "product_name=${DD_PRODUCT_NAME}" \
                      -F "engagement_name=${engagement_name}" \
                      -F "scan_type=${u.scanType}" \
                      -F "file=@${u.file}" \
                      -F "build_id=${BUILD_NUMBER}" \
                      -F "commit_hash=${COMMIT_HASH}" \
                      -F "branch_tag=${branch_name}" \
                      -F "source_code_management_uri=${SOURCE_CODE_URL}" \
                      -F "version=build-${BUILD_NUMBER}" \
                      -F "active=true" \
                      -F "verified=${verifiedFlag}" \
                      -F "do_not_reactivate=false" \
                      -F "close_old_findings=true" \
                      -F "auto_create_context=true" \
                      ${dateFields}
                  """
                } else {
                  echo "⏭️ Skip upload: ${u.file} not found or empty."
                }
              }
            }
          }
        }
      }
    }

    post {
      always { echo 'Pipeline selesai.' }
      failure { echo 'Pipeline gagal.' }
    }
  }
}
