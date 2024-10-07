[<img src="https://img.shields.io/badge/documentation-read-green">](https://docs.deepfence.io/yarahunter/)
[![GitHub license](https://img.shields.io/github/license/deepfence/YaraHunter)](https://github.com/deepfence/YaraHunter/blob/master/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/deepfence/YaraHunter)](https://github.com/deepfence/YaraHunter/stargazers)
[![Hacktoberfest](https://img.shields.io/github/hacktoberfest/2022/deepfence/YaraHunter)](https://github.com/deepfence/YaraHunter/issues)
[![GitHub issues](https://img.shields.io/github/issues/deepfence/YaraHunter)](https://github.com/deepfence/YaraHunter/issues)
[![Slack](https://img.shields.io/badge/slack-@deepfence-blue.svg?logo=slack)](https://join.slack.com/t/deepfence-community/shared_invite/zt-podmzle9-5X~qYx8wMaLt9bGWwkSdgQ)

# YaraHunter

Deepfence YaraHunter scans container images, running Docker containers, and filesystems to find indicators of malware. It uses a [YARA ruleset](https://github.com/deepfence/yara-rules) to identify resources that match known malware signatures, and may indicate that the container or filesystem has been compromised.

YaraHunter can be used in the following ways:

- **At build-and-test**: scan build artifacts in the CI/CD pipeline, reporting on possible indicators of malware
- **At rest**: scan local container images, for example, before they are deployed, to verify they do not contain malware
- **At runtime**: scan running docker containers, for example, if you observe unusual network traffic or CPU activity
- **Against filesystems**: at any time, YaraHunter can scan a local filesystems for indicators of compromise

Key capabilities:

- Scan running and at-rest containers; scan filesystems; scan during CI/CD build operations
- Run anywhere: highly-portable, docker container form factor
- Designed for automation: easy-to-deploy, easy-to-parse JSON output

YaraHunter is a work-in-progress (check the [Roadmap](https://github.com/deepfence/YaraHunter/projects) and [issues list](issues)), and will be integrated into the [ThreatMapper](https://github.com/deepfence/ThreatMapper) threat discovery platform. We welcome any contributions to help to improve this tool.

## Quick Start

For full instructions, refer to the [YaraHunter Documentation](https://docs.deepfence.io/docs/yarahunter/).

![demo gif](demo.gif)

## Example: Finding Indicators of Compromise in a container image

Images may be compromised with the installation of a cryptominer such as XMRig. In the following example, we'll scan a legitimiate cryptominer image that contains the same xmrig software that is often installed through an exploit:

Pull the official **yarahunter** image:

```
docker pull quay.io/deepfenceio/deepfence_malware_scanner_ce:2.4.0
```

or Build it from source clone this repo and run below command
```
make docker
```

Pull the image that needs to be scanned for example `metal3d/xmrig` and scan it:

```
docker pull metal3d/xmrig

docker run -i --rm --name=deepfence-yarahunter \
     -v /var/run/docker.sock:/var/run/docker.sock \
     -v /tmp:/home/deepfence/output \
     quay.io/deepfenceio/deepfence_malware_scanner_ce:2.4.0 \
     --image-name metal3d/xmrig:latest \
     --output=json > xmrig-scan.json
```

This returns, among other things, clear indication of the presence of XMRig. Note that we store the output (`xmrig-scan.json`) for quick and easy manipulation:

```
# Extract the IOC array values.  From these, extract the values of the 'Matched Rule Name' key
cat /tmp/xmrig-scan.json | jq '.IOC[] | ."Matched Rule Name"'
```

This returns a list of the IOCs identified in the container we scanned.

To get table formatted output omit `--output=json` flag

## Get in touch

Thank you for using YaraHunter.

- [<img src="https://img.shields.io/badge/documentation-read-green">](https://docs.deepfence.io/docs/yarahunter/) Start with the documentation
- [<img src="https://img.shields.io/badge/slack-@deepfence-blue.svg?logo=slack">](https://join.slack.com/t/deepfence-community/shared_invite/zt-podmzle9-5X~qYx8wMaLt9bGWwkSdgQ) Got a question, need some help? Find the Deepfence team on Slack
- [![GitHub issues](https://img.shields.io/github/issues/deepfence/YaraHunter)](https://github.com/deepfence/YaraHunter/issues) Got a feature request or found a bug? Raise an issue
- [productsecurity _at_ deepfence _dot_ io](SECURITY.md): Found a security issue? Share it in confidence
- Find out more at [deepfence.io](https://deepfence.io/)

## Security and Support

For any security-related issues in the YaraHunter project, contact [productsecurity _at_ deepfence _dot_ io](SECURITY.md).

Please file GitHub issues as needed, and join the Deepfence Community [Slack channel](https://join.slack.com/t/deepfence-community/shared_invite/zt-podmzle9-5X~qYx8wMaLt9bGWwkSdgQ).

## License

The Deepfence YaraHunter project (this repository) is offered under the [Apache2 license](https://www.apache.org/licenses/LICENSE-2.0).

[Contributions](CONTRIBUTING.md) to Deepfence YaraHunter project are similarly accepted under the Apache2 license, as per [GitHub's inbound=outbound policy](https://docs.github.com/en/github/site-policy/github-terms-of-service#6-contributions-under-repository-license).

# Disclaimer

This tool is not meant to be used for hacking. Please use it only for legitimate purposes like detecting indicator of compromise on the infrastructure you own, not on others' infrastructure. DEEPFENCE shall not be liable for loss of profit, loss of business, other financial loss, or any other loss or damage which may be caused, directly or indirectly, by the inadequacy of YaraHunter for any purpose or use thereof or by any defect or deficiency therein.
