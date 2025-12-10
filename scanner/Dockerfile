# SPDX-FileCopyrightText: the secureCodeBox authors
#
# SPDX-License-Identifier: Apache-2.0

FROM alpine:latest AS build

RUN apk --no-cache add ca-certificates



RUN apt update -y && apt install golang -y

RUN go install github.com/trufflesecurity/trufflehog.git@latest

CMD ["trufflehog"]