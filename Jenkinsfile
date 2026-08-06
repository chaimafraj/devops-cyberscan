pipeline {
    agent any

    options {
        skipDefaultCheckout(true)
        timestamps()
        disableConcurrentBuilds()
    }

    environment {
        COMPOSE_PROJECT_NAME = 'cyberscan'
        NOTIFICATION_EMAIL = 'mahdijr2015@gmail.com'
    }

    stages {
        stage('Checkout GIT') {
            steps {
                echo 'Pulling source code...'
                git branch: 'main',
                    url: 'https://github.com/chaimafraj/devops-cyberscan.git'
            }
        }


        stage('Deploy application') {
            steps {
                sh 'docker compose up --build -d'
            }
        }
    }

    post {
        always {
            script {
                if (fileExists('docker-compose.yml')) {
                    sh script: 'docker compose ps', returnStatus: true
                }

                def buildResult = currentBuild.currentResult ?: 'UNKNOWN'
                mail to: env.NOTIFICATION_EMAIL,
                    from: "CyberScan <${env.NOTIFICATION_EMAIL}>",
                    subject: "Jenkins ${buildResult}: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                    body: """Pipeline finished with status: ${buildResult}

Job: ${env.JOB_NAME}
Build: ${env.BUILD_NUMBER}
Details: ${env.BUILD_URL}
"""
            }
        }
    }
}
