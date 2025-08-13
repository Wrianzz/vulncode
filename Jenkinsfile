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

                    // Image tag lokal
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

        stage('Publish to DefectDojo') {
            steps {
                    script {
                        def uploads = [
                            [file: 'trufflehog-report.json', scanType: 'Trufflehog Scan'],
                            [file: 'grype-report.json',      scanType: 'Anchore Grype'],
                            [file: 'trivy-report.json',      scanType: 'Trivy Scan']
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
                                echo "Skip upload: ${u.file} not found."
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
