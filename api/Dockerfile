FROM adoptopenjdk/openjdk15:centos
ADD . /api
RUN yum install wget -y
RUN wget -P /tmp https://services.gradle.org/distributions/gradle-7.1-bin.zip
RUN yum install unzip -y
RUN unzip -d /opt/gradle /tmp/gradle-7.1-bin.zip
ENV GRADLE_HOME /opt/gradle/gradle-7.1
ENV PATH ${PATH}:${GRADLE_HOME}/bin
WORKDIR /api
RUN gradle build -x test
EXPOSE 8080

ENTRYPOINT ["java","-jar","build/libs/score.jar"]
