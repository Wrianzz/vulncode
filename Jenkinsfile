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

        // Docker image name lokal
        IMAGE_NAME_BASE = 'my-app'

        // SonarQube
        SONAR_PROJECT_KEY = 'vulncode'
        SONAR_HOST_URL = 'http://192.168.88.20:9000'
        SONAR_SCANNER = tool 'sonarqube'
    }

    parameters {
        string(name: 'BRANCHNAME_PARAM', defaultValue: '', description: 'Branch name for manual build')
    }

    stages {
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
                            def result = sh(script: """
                                docker run --rm -v "\$(pwd)":/src -w /src trufflesecurity/trufflehog:latest \
                                filesystem . > trufflehog-report.json || true
                            """, returnStatus: true)
                            archiveArtifacts artifacts: 'trufflehog-report.json', fingerprint: true
                            if (env.branch_name in ['master', 'main'] && result != 0) {
                                error "Secrets found in main branch!"
                            }
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
                                    -Dsonar.host.url=${SONAR_HOST_URL} \
                                    -Dsonar.token=$SONAR_TOKEN \
                                | tee sonarqube_output.txt
                            """

                            env.sonarTaskID = sh(
                                script: "grep -o 'id=[a-f0-9-]\\+' sonarqube_output.txt | cut -d= -f2",
                                returnStdout: true
                            ).trim()
                            echo "SonarQube Task ID: ${env.sonarTaskID}"

                            int maxRetries = 60
                            int retryCount = 0
                            def qualityGateResult = null

                            while (retryCount < maxRetries) {
                                try {
                                    timeout(time: 5, unit: 'SECONDS') {
                                        qualityGateResult = waitForQualityGate abortPipeline: false, credentialsId: env.SONAR_TOKEN
                                    }
                                } catch (err) {
                                    echo "Timeout pada attempt ${retryCount+1} saat memanggil waitForQualityGate. Mencoba lagi..."
                                    qualityGateResult = [status: 'IN_PROGRESS']
                                }

                                echo "Attempt ${retryCount+1}: SonarQube Quality Gate status = ${qualityGateResult.status}"
                                if (qualityGateResult.status != 'IN_PROGRESS' && qualityGateResult.status != 'PENDING') {
                                    break
                                }
                                retryCount++
                            }

                            if (qualityGateResult.status == 'IN_PROGRESS' || qualityGateResult.status == 'PENDING') {
                                echo "Quality Gate check timed out after ${maxRetries} retries. Please verify the SonarQube server for details."
                            }
                            if (qualityGateResult.status == 'ERROR') {
                                echo "SonarQube Quality Gate gagal dengan status: ${qualityGateResult.status}. Pipeline bypassed."
                            }

                            env.analysisId = sh(
                                script: """
                                    curl -s -u "${SONAR_TOKEN}:" \
                                        "${SONAR_HOST_URL}/api/ce/task?id=${env.sonarTaskID}" \
                                        | jq -r '.task.analysisId'
                                """,
                                returnStdout: true
                            ).trim()
                            echo "SonarQube Analysis ID: ${env.analysisId}"

                            sh """
                                curl -s -u "${SONAR_TOKEN}:" \
                                    "${SONAR_HOST_URL}/api/issues/search?analysisId=${env.analysisId}" \
                                    -o sonarqube-detailed-scan-report.json
                            """

                            archiveArtifacts artifacts: 'sonarqube-detailed-scan-report.json', fingerprint: true
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
                        [file: 'sonarqube-detailed-scan-report.json', scanType: 'SonarQube Scan']
                    ]
                   
                    uploads.each { u ->
                        if (fileExists(u.file)) {
                            defectDojoPublisher(
                                artifact: u.file,
                                productName: "${DD_PRODUCT_NAME}",
                                scanType: "${u.scanType}",
                                engagementName: "${DD_ENGAGEMENT}",
                                defectDojoCredentialsId: 'defectdojo-api-key',
                                sourceCodeUrl: "${SOURCE_CODE_URL}",
                                branchTag: "${BRANCH_TAG}"
                            )
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
