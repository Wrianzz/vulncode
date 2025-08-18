pipeline {
    agent any

    environment {
        // Public repo kamu
        gitUrl = 'https://github.com/Wrianzz/vulncode.git'

        // DefectDojo
        DD_PRODUCT_NAME = 'DevSecOps'
        DD_ENGAGEMENT = 'Vulnerable-Code'
        SOURCE_CODE_URL = 'https://github.com/Wrianzz/vulncode.git'
        DD_URL = 'http://192.168.88.20:8280'
        
        // Docker image name lokal
        IMAGE_NAME_BASE = 'my-app'

        // SonarQube
        SONAR_PROJECT_KEY = 'vulnerable-code'
        SONAR_HOST_URL = 'http://192.168.88.20:9000'
        SONAR_SCANNER = tool 'sonarqube'
    }

    parameters {
        string(name: 'COMMIT_HASH', defaultValue: '', description: 'Commit Message/Hash for build (default : Commit SHA Git)')
    }

    stages {
      stage('Init') {
        steps {
          script {
            echo "🚀 Starting build number: ${env.BUILD_NUMBER}"
    
            // Commit hash (punyamu sudah oke)
            if (!params.COMMIT_HASH?.trim()) {
              env.COMMIT_HASH = sh(script: 'git rev-parse HEAD', returnStdout: true).trim()
            } else {
              env.COMMIT_HASH = params.COMMIT_HASH
            }
    
            // --- DETEKSI BRANCH OTOMATIS (pra-checkout) ---
            // Urutan prioritas:
            // 1) PR build: CHANGE_BRANCH (source branch)
            // 2) Multibranch: BRANCH_NAME
            // 3) Freestyle Git SCM: GIT_BRANCH (biasanya "origin/xxx" -> buang prefix)
            // 4) Param manual (opsional), terakhir default 'main'
            env.branch_name = (
                env.CHANGE_BRANCH ?:                      // e.g. feature/foo pada PR
                env.BRANCH_NAME   ?:                      // multibranch: "main", "prod", dll
                (env.GIT_BRANCH?.replaceAll('^origin/','')) ?: // freestyle: "origin/main" -> "main"
                params.BRANCHNAME_PARAM?.trim() ?: 
                'main'
            )
    
            // Set sementara; nanti kita "finalize" setelah checkout
            env.BRANCH_TAG = env.branch_name
    
            echo "🔖 Tentative branch: ${env.branch_name}"
            echo "🔖 Tentative BRANCH_TAG: ${env.BRANCH_TAG}"
          }
        }
      }
    
      stage('Checkout') {
        steps {
          script {
            // Pakai branch yang sudah kita deteksi di Init
            cleanWs()
            git branch: env.branch_name, url: env.gitUrl
    
            // --- FINALISASI (pasca-checkout) ---
            // Di beberapa setup non-multibranch, git bisa checkout detached HEAD.
            // Kita coba perkuat deteksi; kalau gagal, tetap pakai nilai sebelumnya.
            def after = sh(
              script: '''
                # Coba ambil nama branch "asli"
                name=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
                if [ "$name" = "HEAD" ] || [ -z "$name" ]; then
                  # Fallback: coba baca remote tracking
                  name=$(git branch -r --contains HEAD | head -n1 | sed -E "s/.*origin\\///" | tr -d " ")
                fi
                echo "$name"
              ''',
              returnStdout: true
            ).trim()
    
            if (after) {
              env.branch_name = after
              env.BRANCH_TAG  = after
            }
    
            // Build number buat image tag (punyamu udah oke)
            env.imageTag = env.BUILD_NUMBER
    
            echo "✅ Final branch: ${env.branch_name}"
            echo "🏷️  BRANCH_TAG: ${env.BRANCH_TAG}"
          }
        }
      }

        stage('Test (Security)') {
            parallel {
                stage('Secrets Scan (TruffleHog)') {
                    steps {
                        script {
                            def result = sh(script: 'trufflehog filesystem . --json > trufflehog-report.json', returnStatus: true)

                            sh 'cat trufflehog-report.json || echo "Report kosong atau tidak terbaca"'

                            if (env.branch_name in ['master', 'main'] && result != 0) {
                                echo "Secret ditemukan oleh TruffleHog di branch ${env.branch_name}. Pipeline bypassed."
                            } else {
                                echo "Secret scanning selesai. ${env.branch_name in ['master', 'main'] ? 'Blocking on any secret (bypassed).' : 'Continuing despite findings.'}"
                            }
                            archiveArtifacts artifacts: 'trufflehog-report.json', fingerprint: true
                        }
                    }
                }
                stage('SCA (Grype)') {
                    steps {
                        script {
                            sh """
                                docker run --rm -v "\$(pwd)":/src -w /src anchore/grype:latest \
                                dir:/src -o json > grype-report.json || true
                            """
                            archiveArtifacts artifacts: 'grype-report.json', fingerprint: true
                        }
                    }
                }
            }
        }

        stage('Build Image') {
            steps {
                script {
                    sh "docker build --network=host -t ${IMAGE_NAME_BASE}:${env.imageTag} ."
                }
            }
        }

        stage('Image Scan (Trivy)') {
            steps {
                script {
                    def trivyArgs = (env.branch_name in ['master', 'main']) ? '--severity HIGH,CRITICAL --exit-code 1' : ''
                    def result = sh(script: """
                        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest \
                        image ${trivyArgs} --format json ${IMAGE_NAME_BASE}:${env.imageTag} \
                        > trivy-report.json || true
                    """, returnStatus: true)
                    archiveArtifacts artifacts: 'trivy-report.json', fingerprint: true
                    if (env.branch_name in ['master', 'main'] && result != 0) {
                        error "Critical vulnerabilities found in main branch image!"
                    }
                }
            }
        }
        
        stage('SAST (SonarQube)') {
            steps {
                withCredentials([string(credentialsId: 'sonarqube-token', variable: 'SONAR_TOKEN')]) {
                    withSonarQubeEnv("${env.SONAR_ENV}") {
                        script {
                            sh """
                                ${SONAR_SCANNER}/bin/sonar-scanner \
                                    -Dsonar.projectKey=${SONAR_PROJECT_KEY} \
                                    -Dsonar.sources=. \
                                    -Dsonar.token=$SONAR_TOKEN \
                                | tee sonarqube_out.txt
                                """

                            // Ambil taskId yang pertama muncul
                            env.sonarTaskID = sh(
                                script: "grep -o 'id=[a-f0-9-]\\+' sonarqube_out.txt | cut -d= -f2",
                                returnStdout: true
                            ).trim()
                            echo "SonarQube Task ID: ${env.sonarTaskID}"
        
                            // Tunggu sampai task selesai
                            def taskStatus = ""
                            def maxWait = 120 // 120 detik
                            def waited = 0
                            while (waited < maxWait) {
                                def response = sh(
                                    script: """curl -s -u "${SONAR_TOKEN}:" \
                                        "${SONAR_HOST_URL}/api/ce/task?id=${env.sonarTaskID}" """,
                                    returnStdout: true
                                )
        
                                taskStatus = sh(
                                    script: "echo '${response}' | jq -r '.task.status'",
                                    returnStdout: true
                                ).trim()
        
                                if (taskStatus in ["SUCCESS", "FAILED", "CANCELED"]) {
                                    env.analysisId = sh(
                                        script: "echo '${response}' | jq -r '.task.analysisId'",
                                        returnStdout: true
                                    ).trim()
                                    break
                                }
                                sleep 3
                                waited += 3
                            }
        
                            echo "Task Status: ${taskStatus}"
                            echo "SonarQube Analysis ID: ${env.analysisId}"
        
                            sh """
                                curl -s -u "${SONAR_TOKEN}:" \
                                "${SONAR_HOST_URL}/api/hotspots/search?project=${SONAR_PROJECT_KEY}" \
                                -o sonarqube-scan-report.json
                               """
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
                        [file: 'trufflehog-report.json', scanType: 'Trufflehog Scan'],
                        [file: 'grype-report.json',      scanType: 'Anchore Grype'],
                        [file: 'trivy-report.json',      scanType: 'Trivy Scan'],
                        [file: 'sonarqube-scan-report.json', scanType: 'SonarQube Scan']
                    ]

                    uploads.each { u ->
                        if (fileExists(u.file)) {
                            echo "📤 Processing ${u.file} for DefectDojo..."

                            withCredentials([string(credentialsId: 'defectdojo-api-key', variable: 'DD_API_KEY')]) {
                                def scanExists = sh(
                                     script: """
                                        curl -s -G "${DD_URL}/api/v2/tests/" \
                                          -H "Authorization: Token ${DD_API_KEY}" \
                                          --data-urlencode "engagement__name=${DD_ENGAGEMENT}" \
                                          --data-urlencode "scan_type=${u.scanType}" \
                                          | jq '.count'
                                    """,
                                    returnStdout: true
                                ).trim()

                                if (scanExists != "0") {
                                    echo "🔄 Reimport scan for ${u.scanType}"
                                    sh """curl -X POST "${DD_URL}/api/v2/reimport-scan/" \
                                          -H "Authorization: Token ${DD_API_KEY}" \
                                          -F "product_name=${DD_PRODUCT_NAME}" \
                                          -F "engagement_name=${DD_ENGAGEMENT}" \
                                          -F "scan_type=${u.scanType}" \
                                          -F "file=@${u.file}" \
                                          -F "build_id=${env.BUILD_NUMBER}" \
                                          -F "commit_hash=${env.COMMIT_HASH}" \
                                          -F "branch_tag=${BRANCH_TAG}" \
                                          -F "source_code_management_uri=${SOURCE_CODE_URL}" \
                                          -F "version=build-${env.BUILD_NUMBER}" \
                                          -F "active=true" \
                                          -F "verified=true" \
                                          -F "do_not_reactivate=false" \
                                          -F "close_old_findings=true"
                                    """
                                } else {
                                    defectDojoPublisher(
                                    artifact: u.file,
                                    productName: "${DD_PRODUCT_NAME}",
                                    scanType: "${u.scanType}",
                                    engagementName: "${DD_ENGAGEMENT}",
                                    defectDojoCredentialsId: 'defectdojo-api-key',
                                    sourceCodeUrl: "${SOURCE_CODE_URL}"
                                    )
                                }
                            }
                        } else {
                            echo "⏭️ Skip upload: ${u.file} tidak ada atau kosong."
                        }
                    }
                }
            }
        }
    }
    
    post {
         always {
            echo "Pipeline selesai."
          }
        failure {
             echo "Pipeline gagal."
       }
    }
}
