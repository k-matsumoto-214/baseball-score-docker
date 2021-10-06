FROM node:16

ENV LANG C.UTF-8
ENV TZ Asia/Tokyo

RUN npm install --global @vue/cli @vue/cli-init

ADD . /front
WORKDIR /front
RUN npm install
RUN npm run build
EXPOSE 3000
ENTRYPOINT ["npm","run","start"]

