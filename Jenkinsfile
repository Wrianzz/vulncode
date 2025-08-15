pipeline {
    agent any

    environment {
        // Public repo kamu
        gitUrl = 'https://github.com/Wrianzz/vulncode.git'

        // DefectDojo
        DD_PRODUCT_NAME = 'my-product'
        DD_ENGAGEMENT = 'ci/cd'
        SOURCE_CODE_URL = 'https://github.com/Wrianzz/vulncode.git'
        BRANCH_TAG = 'main'
        DD_URL = 'http://192.168.88.20:8280'
        DD_API = credentials('defectdojo-api-key')

        // Docker image name lokal
        IMAGE_NAME_BASE = 'my-app'

        // SonarQube
        SONAR_PROJECT_KEY = 'vulnerable-code'
        SONAR_HOST_URL = 'http://192.168.88.20:9000'
        SONAR_SCANNER = tool 'sonarqube'
    }

    parameters {
        string(name: 'BRANCHNAME_PARAM', defaultValue: '', description: 'Branch name for manual build')
    }

    stages {
        stage('Init') {
            steps {
                script {
                    echo "🚀 Starting build number: ${env.BUILD_NUMBER}"
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
                            echo "Uploading ${u.file} to DefectDojo..."
                            sh """
                                curl -X POST "${DD_URL}/api/v2/reimport-scan/" \
                                  -H "Authorization: Token ${DD_API}" \
                                  -F "product_name=${DD_PRODUCT_NAME} \
                                  -F "engagement_name=${DD_ENGAGEMENT}" \
                                  -F "scan_type=${u.scanType}" \
                                  -F "file=@${u.file}" \
                                  -F "build_id=${env.BUILD_NUMBER}" \
                                  -F "branch_tag=${BRANCH_TAG}" \
                                  -F "source_code_management_uri=${SOURCE_CODE_URL}" \
                                  -F "version=build-${env.BUILD_NUMBER}" \
                                  -F "active=true" \
                                  -F "verified=true" \
                                  -F "close_old_findings=false"
                            """
                        } else {
                            echo "Skip upload: ${u.file} tidak ada atau kosong."
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
