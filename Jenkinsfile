pipeline {
    agent any

    environment {
        DEFECTDOJO_API_KEY_ID = 'DEFECTDOJO_API_KEY_ID'

        DD_PRODUCT_NAME = 'my-product'
        DD_ENGAGEMENT   = 'ci/cd'
        SOURCE_CODE_URL = 'https://github.com/Wrianzz/vulncode.git'
        BRANCH_TAG      = 'main'

        IMAGE_NAME = "my-app"
    }

    options {
        timestamps()
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                script {
                    if (env.GIT_BRANCH) {
                        env.BRANCH_TAG = env.GIT_BRANCH.replaceAll('origin/', '')
                    }
                }
            }
        }

        stage('Build (optional)') {
            steps {
                echo "Installing Python dependencies..."
                sh 'pip install -r requirements.txt || true'
            }
        }

        stage('TruffleHog (secrets scan)') {
            steps {
                script {
                    sh '''
                    docker run --rm -v "$(pwd)":/src -w /src trufflesecurity/trufflehog:latest \
                      filesystem --format json . > trufflehog-report.json || true
                    '''
                    archiveArtifacts artifacts: 'trufflehog-report.json', fingerprint: true
                }
            }
        }

        stage('Build Docker image (for Trivy/Grype)') {
            steps {
                script {
                    sh "docker build -t ${IMAGE_NAME}:${env.BUILD_NUMBER} . || true"
                }
            }
        }

        stage('Trivy scan (image)') {
            steps {
                script {
                    sh """
                    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest \
                      image --format json --quiet --output trivy-report.json ${IMAGE_NAME}:${env.BUILD_NUMBER} || true
                    """
                    archiveArtifacts artifacts: 'trivy-report.json', fingerprint: true
                }
            }
        }

        stage('Grype scan (image)') {
            steps {
                script {
                    sh """
                    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock anchore/grype:latest \
                      ${IMAGE_NAME}:${env.BUILD_NUMBER} -o json > grype-report.json || true
                    """
                    archiveArtifacts artifacts: 'grype-report.json', fingerprint: true
                }
            }
        }

        stage('Publish all scans to DefectDojo') {
            steps {
                withCredentials([string(credentialsId: "${DEFECTDOJO_API_KEY_ID}", variable: 'DD_API_KEY')]) {
                    script {
                        def uploads = [
                            [file: 'trufflehog-report.json', scanType: 'TruffleHog Scan'],
                            [file: 'trivy-report.json',      scanType: 'Trivy Scan'],
                            [file: 'grype-report.json',      scanType: 'Grype Scan']
                        ]

                        uploads.each { u ->
                            if (fileExists(u.file)) {
                                echo "Publishing ${u.file} => DefectDojo as ${u.scanType}"
                                defectDojoPublisher(
                                    artifact: u.file,
                                    productName: "${DD_PRODUCT_NAME}",
                                    scanType: "${u.scanType}",
                                    engagementName: "${DD_ENGAGEMENT}",
                                    defectDojoCredentialsId: DD_API_KEY,
                                    sourceCodeUrl: "${SOURCE_CODE_URL}",
                                    branchTag: "${BRANCH_TAG}"
                                )
                            } else {
                                echo "File not found, skip: ${u.file}"
                            }
                        }
                    }
                }
            }
        }
    }

    post {
        always {
            echo "Pipeline selesai. Semua artifacts sudah di-archive."
        }
        failure {
            echo "Pipeline gagal."
        }
    }
}
