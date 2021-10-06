FROM adoptopenjdk/openjdk15:jdk-15.0.2_7-centos
COPY . .
RUN yum install wget -y
RUN wget -P /tmp https://services.gradle.org/distributions/gradle-7.1-bin.zip
RUN yum install unzip -y
RUN unzip -d /opt/gradle /tmp/gradle-7.1-bin.zip
ENV GRADLE_HOME /opt/gradle/gradle-7.1
ENV PATH ${PATH}:${GRADLE_HOME}/bin
RUN gradle build -x test

ENTRYPOINT ["/bin/sh", "-c", "while :; do sleep 10; done"]
