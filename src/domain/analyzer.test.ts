import { describe, expect, it } from 'vitest'
import { analyzeConfiguration, analyzePolicies } from './analyzer'

const configuration = `
config firewall policy
    edit 10
        set name "Accès Internet global"
        set srcintf "lan"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
    edit 20
        set name "Web publié"
        set srcintf "lan"
        set dstintf "wan1"
        set action accept
        set srcaddr "Postes"
        set dstaddr "Serveur-Web"
        set schedule "always"
        set service "HTTPS"
        set logtraffic all
    next
end
`

const serviceComparisonConfiguration = (
  definitions: string,
  coveringService: string,
  candidateService: string,
) => `
config firewall service custom
${definitions}
end
config firewall policy
  edit 1
    set srcintf "lan"
    set dstintf "wan"
    set srcaddr "Postes"
    set dstaddr "Serveur"
    set action accept
    set service "${coveringService}"
    set logtraffic all
  next
  edit 2
    set srcintf "lan"
    set dstintf "wan"
    set srcaddr "Postes"
    set dstaddr "Serveur"
    set action accept
    set service "${candidateService}"
    set logtraffic all
  next
end`

describe('analyzeConfiguration', () => {
  it('identifie une règle spécifique masquée par une règle globale antérieure', () => {
    const result = analyzeConfiguration(configuration)

    expect(result.policies).toHaveLength(2)
    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ policyId: '10', category: 'permissive', severity: 'critical' }),
        expect.objectContaining({ policyId: '20', category: 'shadowed', shadowedBy: '10' }),
      ]),
    )
    expect(result.findings).not.toEqual(
      expect.arrayContaining([expect.objectContaining({ policyId: '10', category: 'shadowed' })]),
    )
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        policyId: '20',
        category: 'shadowed',
        evidence: expect.arrayContaining([
          'Services couverts : ALL couvre HTTPS',
          'Sources couvertes : all couvre Postes',
          'Destinations couvertes : all couvre Serveur-Web',
        ]),
      }),
    ]))
  })

  it('ne masque pas une règle lorsque les services sont différents', () => {
    const differentServices = configuration
      .replace('set service "ALL"', 'set service "HTTP"')

    expect(analyzeConfiguration(differentServices).findings).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '20', category: 'shadowed' }),
    ]))
  })

  it('signale une règle accept rendue inatteignable par un deny couvrant antérieur', () => {
    const denyBeforeAccept = configuration
      .replace('set action accept', 'set action deny')
      .replace('set name "Accès Internet global"', 'set name "Blocage global"')

    expect(analyzeConfiguration(denyBeforeAccept).findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        policyId: '20',
        category: 'shadowed',
        shadowedBy: '10',
        detail: expect.stringContaining('refusé'),
      }),
    ]))
  })

  it('ne traite pas un deny spécifique comme une exception masquant un accept plus large', () => {
    const denyException = `
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set schedule "always"
        set service "HTTPS"
        set logtraffic all
    next
    edit 2
        set srcintf "lan"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
end`

    expect(analyzeConfiguration(denyException).findings).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'shadowed' }),
    ]))
    expect(analyzeConfiguration(denyException).findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'overlap', overlapsWith: '1' }),
    ]))
  })

  it('ne masque pas une règle ALL lorsqu’une règle précédente ne couvre qu’un service', () => {
    const specificBeforeAll = `
config firewall policy
    edit 1
        set name "HTTPS spécifique"
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "Postes"
        set dstaddr "Internet"
        set action accept
        set schedule "always"
        set service "HTTPS"
        set logtraffic all
    next
    edit 2
        set name "Tous services"
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "Postes"
        set dstaddr "Internet"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
end`

    const findings = analyzeConfiguration(specificBeforeAll).findings
    expect(findings).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'shadowed' }),
    ]))
    expect(findings).toEqual(expect.arrayContaining([
      expect.objectContaining({
        policyId: '2',
        category: 'overlap',
        overlapsWith: '1',
        detail: expect.stringContaining('n’est pas masquée'),
        evidence: expect.arrayContaining([
          'Services en intersection : HTTPS avec ALL',
          'La règle #2 reste applicable au trafic non couvert par la règle #1',
        ]),
      }),
    ]))
  })

  it('ne considère pas deux définitions sans plage de ports comme équivalentes', () => {
    const servicesWithoutPorts = `
config firewall service custom
    edit "PING"
        set protocol ICMP
    next
    edit "ALL"
        set protocol IP
    next
end
config firewall policy
    edit 219
        set srcintf "any"
        set dstintf "wan"
        set srcaddr "LAN"
        set dstaddr "Internet"
        set action accept
        set service "PING"
        set logtraffic all
    next
    edit 426
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "LAN"
        set dstaddr "Internet"
        set action accept
        set service "ALL"
        set logtraffic all
    next
end`

    expect(analyzeConfiguration(servicesWithoutPorts).findings).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '426', category: 'shadowed', shadowedBy: '219' }),
    ]))
  })

  it('ne confond pas un port TCP avec le même port UDP', () => {
    const protocolConfiguration = `
config firewall service custom
    edit "TCP-53"
        set tcp-portrange 53
    next
    edit "UDP-53"
        set udp-portrange 53
    next
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "Postes"
        set dstaddr "DNS"
        set action accept
        set service "TCP-53"
        set logtraffic all
    next
    edit 2
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "Postes"
        set dstaddr "DNS"
        set action accept
        set service "UDP-53"
        set logtraffic all
    next
end`

    expect(analyzeConfiguration(protocolConfiguration).findings).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'shadowed' }),
    ]))
  })

  it('compare les plages de ports source en plus des ports destination', () => {
    const result = analyzeConfiguration(serviceComparisonConfiguration(`
    edit "SOURCE-LIMITEE"
        set tcp-portrange 443:1024-2000
    next
    edit "SOURCE-HORS-PLAGE"
        set tcp-portrange 443:3000
    next`, 'SOURCE-LIMITEE', 'SOURCE-HORS-PLAGE'))

    expect(result.findings).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: expect.stringMatching(/shadowed|duplicate|overlap/) }),
    ]))
  })

  it('reconnaît une plage de ports source qui couvre une source précise', () => {
    const result = analyzeConfiguration(serviceComparisonConfiguration(`
    edit "SOURCE-LARGE"
        set tcp-portrange 443:1024-65535
    next
    edit "SOURCE-PRECISE"
        set tcp-portrange 443:3000
    next`, 'SOURCE-LARGE', 'SOURCE-PRECISE'))

    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'shadowed' }),
    ]))
  })

  it('compare les plages SCTP comme les plages TCP et UDP', () => {
    const result = analyzeConfiguration(serviceComparisonConfiguration(`
    edit "SCTP-LARGE"
        set sctp-portrange 5000-6000
    next
    edit "SCTP-PRECIS"
        set sctp-portrange 5500
    next`, 'SCTP-LARGE', 'SCTP-PRECIS'))

    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'shadowed' }),
    ]))
  })

  it('reconnaît qu’un service ICMP sans type couvre un type ICMP précis', () => {
    const result = analyzeConfiguration(serviceComparisonConfiguration(`
    edit "ICMP-TOUS"
        set protocol ICMP
        unset icmptype
        unset icmpcode
    next
    edit "ICMP-ECHO"
        set protocol ICMP
        set icmptype 8
        set icmpcode 0
    next`, 'ICMP-TOUS', 'ICMP-ECHO'))

    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'shadowed' }),
    ]))
  })

  it('ne confond pas deux types ICMP distincts', () => {
    const result = analyzeConfiguration(serviceComparisonConfiguration(`
    edit "ICMP-ECHO"
        set protocol ICMP
        set icmptype 8
    next
    edit "ICMP-UNREACHABLE"
        set protocol ICMP
        set icmptype 3
    next`, 'ICMP-ECHO', 'ICMP-UNREACHABLE'))

    expect(result.findings).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'shadowed' }),
    ]))
  })

  it('compare aussi le code ICMP lorsque le type est identique', () => {
    const result = analyzeConfiguration(serviceComparisonConfiguration(`
    edit "ICMP-CODE-1"
        set protocol ICMP
        set icmptype 3
        set icmpcode 1
    next
    edit "ICMP-CODE-2"
        set protocol ICMP
        set icmptype 3
        set icmpcode 2
    next`, 'ICMP-CODE-1', 'ICMP-CODE-2'))

    expect(result.findings).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'shadowed' }),
    ]))
  })

  it('compare les numéros de protocole IP et leur valeur générique', () => {
    const protocolDefinitions = `
    edit "IP-TOUS"
        set protocol IP
    next
    edit "GRE"
        set protocol IP
        set protocol-number 47
    next
    edit "ESP"
        set protocol IP
        set protocol-number 50
    next
    edit "HTTPS-CUSTOM"
      set tcp-portrange 443
    next`

    expect(analyzeConfiguration(serviceComparisonConfiguration(
      protocolDefinitions, 'IP-TOUS', 'GRE',
    )).findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'shadowed' }),
    ]))
    expect(analyzeConfiguration(serviceComparisonConfiguration(
      protocolDefinitions, 'GRE', 'ESP',
    )).findings).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'shadowed' }),
    ]))
    expect(analyzeConfiguration(serviceComparisonConfiguration(
      protocolDefinitions, 'IP-TOUS', 'HTTPS-CUSTOM',
    )).findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'shadowed' }),
    ]))
  })

  it('ne confond jamais les familles ICMP et ICMP6', () => {
    const result = analyzeConfiguration(serviceComparisonConfiguration(`
    edit "PING4"
        set protocol ICMP
        set icmptype 8
    next
    edit "PING6"
        set protocol ICMP6
        set icmptype 128
    next`, 'PING4', 'PING6'))

    expect(result.findings).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'shadowed' }),
    ]))
  })

    it('développe les groupes de services imbriqués avant de comparer', () => {
    const groupedServices = `
  config firewall service custom
    edit "HTTP-CUSTOM"
      set tcp-portrange 80
    next
    edit "HTTPS-CUSTOM"
      set tcp-portrange 443
    next
  end
  config firewall service group
    edit "WEB"
      set member "HTTP-CUSTOM" "HTTPS-CUSTOM"
    next
    edit "APPLICATIONS"
      set member "WEB"
    next
  end
  config firewall policy
    edit 1
      set srcintf "lan"
      set dstintf "wan"
      set srcaddr "Postes"
      set dstaddr "Internet"
      set action accept
      set service "APPLICATIONS"
      set logtraffic all
    next
    edit 2
      set srcintf "lan"
      set dstintf "wan"
      set srcaddr "Postes"
      set dstaddr "Internet"
      set action accept
      set service "HTTPS-CUSTOM"
      set logtraffic all
    next
  end`

    expect(analyzeConfiguration(groupedServices).findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'shadowed' }),
    ]))
    })

  it('propose de restreindre chaque dimension globale d’une règle permissive', () => {
    const finding = analyzeConfiguration(configuration).findings.find(
      (candidate) => candidate.policyId === '10' && candidate.category === 'permissive',
    )

    expect(finding?.recommendation).toMatchObject({
      summary: expect.stringContaining('moindre privilège'),
      actions: expect.arrayContaining([
        expect.stringContaining('sources'),
        expect.stringContaining('destinations'),
        expect.stringContaining('services'),
      ]),
      reference: {
        title: 'Fortinet - Firewall policy',
        url: expect.stringContaining('docs.fortinet.com/document/fortigate/'),
      },
    })
  })

  it('propose une remédiation prudente et ciblée pour une règle masquée', () => {
    const finding = analyzeConfiguration(configuration).findings.find(
      (candidate) => candidate.policyId === '20' && candidate.category === 'shadowed',
    )

    expect(finding?.recommendation).toMatchObject({
      summary: expect.stringContaining('règle #10'),
      actions: expect.arrayContaining([
        expect.stringContaining('compteurs'),
        expect.stringContaining('désactiver'),
      ]),
      cli: expect.stringContaining('edit 20'),
    })
  })

  it('propose la commande FortiOS de journalisation pour un manque de visibilité', () => {
    const withoutLogging = configuration.replace('set logtraffic all', 'set logtraffic disable')
    const finding = analyzeConfiguration(withoutLogging).findings.find(
      (candidate) => candidate.policyId === '10' && candidate.category === 'visibility',
    )

    expect(finding?.recommendation).toMatchObject({
      actions: expect.arrayContaining([expect.stringContaining('journalisation')]),
      cli: expect.stringMatching(/edit 10[\s\S]*set logtraffic all/),
      reference: { title: 'Fortinet - Firewall policy' },
    })
  })

    it('détecte la couverture réelle entre deux sous-réseaux et deux services personnalisés', () => {
    const semanticConfiguration = `
  config firewall address
    edit "LAN-24"
      set subnet 10.10.0.0 255.255.255.0
    next
    edit "LAN-25"
      set subnet 10.10.0.128 255.255.255.128
    next
  end
  config firewall service custom
    edit "WEB-LARGE"
      set tcp-portrange 8000-8100
    next
    edit "WEB-SMALL"
      set tcp-portrange 8050-8060
    next
  end
  config firewall policy
    edit 1
      set srcintf "lan"
      set dstintf "dmz"
      set srcaddr "LAN-24"
      set dstaddr "Server"
      set action accept
      set service "WEB-LARGE"
      set logtraffic all
    next
    edit 2
      set srcintf "lan"
      set dstintf "dmz"
      set srcaddr "LAN-25"
      set dstaddr "Server"
      set action accept
      set service "WEB-SMALL"
      set logtraffic all
    next
  end`

    expect(analyzeConfiguration(semanticConfiguration).findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'shadowed', shadowedBy: '1' }),
    ]))
    })

    it('détecte la couverture réelle d’une plage IP FortiGate', () => {
    const rangeConfiguration = `
  config firewall address
    edit "RANGE-LARGE"
      set type iprange
      set start-ip 192.0.2.10
      set end-ip 192.0.2.100
    next
    edit "RANGE-SMALL"
      set type iprange
      set start-ip 192.0.2.30
      set end-ip 192.0.2.40
    next
  end
  config firewall policy
    edit 1
      set srcintf "lan"
      set dstintf "wan"
      set srcaddr "RANGE-LARGE"
      set dstaddr "all"
      set action accept
      set service "HTTPS"
      set logtraffic all
    next
    edit 2
      set srcintf "lan"
      set dstintf "wan"
      set srcaddr "RANGE-SMALL"
      set dstaddr "all"
      set action accept
      set service "HTTPS"
      set logtraffic all
    next
  end`

    expect(analyzeConfiguration(rangeConfiguration).findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'shadowed' }),
    ]))
    })

    it('signale une intersection partielle sans la qualifier de règle masquée', () => {
    const overlapConfiguration = `
  config firewall address
    edit "FIRST-RANGE"
      set type iprange
      set start-ip 10.0.0.1
      set end-ip 10.0.0.100
    next
    edit "SECOND-RANGE"
      set type iprange
      set start-ip 10.0.0.80
      set end-ip 10.0.0.150
    next
  end
  config firewall policy
    edit 1
      set srcintf "lan"
      set dstintf "wan"
      set srcaddr "FIRST-RANGE"
      set dstaddr "all"
      set action accept
      set service "HTTPS"
      set logtraffic all
    next
    edit 2
      set srcintf "lan"
      set dstintf "wan"
      set srcaddr "SECOND-RANGE"
      set dstaddr "all"
      set action accept
      set service "HTTPS"
      set logtraffic all
    next
  end`

    const findings = analyzeConfiguration(overlapConfiguration).findings
    expect(findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'overlap', overlapsWith: '1' }),
    ]))
    expect(findings).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'shadowed' }),
    ]))
    })

  it('isole les politiques de chaque VDOM même lorsque leurs identifiants sont identiques', () => {
    const multiVdomConfiguration = `
config vdom
    edit "root"
        config firewall policy
            edit 1
                set name "Root global"
                set srcintf "lan"
                set dstintf "wan"
                set srcaddr "all"
                set dstaddr "all"
                set action accept
                set service "ALL"
                set logtraffic all
            next
        end
    next
    edit "branch"
        config firewall policy
            edit 1
                set name "Branch spécifique"
                set srcintf "lan"
                set dstintf "wan"
                set srcaddr "Postes"
                set dstaddr "Internet"
                set action accept
                set service "HTTPS"
                set logtraffic all
            next
        end
    next
end`

    const result = analyzeConfiguration(multiVdomConfiguration)

    expect(result.policies).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: '1', name: 'Root global', vdom: 'root' }),
      expect.objectContaining({ id: '1', name: 'Branch spécifique', vdom: 'branch' }),
    ]))
    expect(result.findings).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ policyName: 'Branch spécifique', category: 'shadowed' }),
    ]))
  })

  it('distingue une règle dupliquée d’une règle simplement masquée', () => {
    const duplicateConfiguration = `
config firewall policy
    edit 1
        set name "Web original"
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "Postes"
        set dstaddr "Internet"
        set action accept
        set schedule "always"
        set service "HTTPS"
        set logtraffic all
    next
    edit 2
        set name "Web copie"
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "Postes"
        set dstaddr "Internet"
        set action accept
        set schedule "always"
        set service "HTTPS"
        set logtraffic all
    next
end`

    const findings = analyzeConfiguration(duplicateConfiguration).findings
    expect(findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'duplicate', duplicateOf: '1' }),
    ]))
    expect(findings).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'shadowed' }),
    ]))
  })

  it('analyse les politiques IPv6 sans les comparer aux politiques IPv4', () => {
    const ipv6Configuration = `
config firewall policy
    edit 1
        set name "IPv4"
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
        set logtraffic all
    next
end
config firewall policy6
    edit 1
        set name "IPv6 global"
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all_ipv6"
        set dstaddr "all_ipv6"
        set action accept
        set service "ALL"
        set logtraffic all
    next
    edit 2
        set name "IPv6 web"
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "LAN6"
        set dstaddr "Internet6"
        set action accept
        set service "HTTPS"
        set logtraffic all
    next
end`

    const result = analyzeConfiguration(ipv6Configuration)

    expect(result.policies).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: '1', name: 'IPv4', family: 'ipv4' }),
      expect.objectContaining({ id: '1', name: 'IPv6 global', family: 'ipv6' }),
      expect.objectContaining({ id: '2', name: 'IPv6 web', family: 'ipv6' }),
    ]))
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyName: 'IPv6 global', category: 'permissive' }),
      expect.objectContaining({ policyName: 'IPv6 web', category: 'shadowed' }),
    ]))
    expect(result.findings).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ policyName: 'IPv6 global', category: 'duplicate' }),
    ]))
  })

  it('compare réellement les préfixes IPv6', () => {
    const ipv6PrefixConfiguration = `
config firewall address6
    edit "IPv6-LARGE"
        set subnet6 2001:db8::/32
    next
    edit "IPv6-SMALL"
        set subnet6 2001:db8:1::/48
    next
end
config firewall policy6
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "IPv6-LARGE"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
        set logtraffic all
    next
    edit 2
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "IPv6-SMALL"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
        set logtraffic all
    next
end`

    expect(analyzeConfiguration(ipv6PrefixConfiguration).findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'shadowed', shadowedBy: '1' }),
    ]))
  })

  it('résout les zones FortiGate dans la couverture des interfaces', () => {
    const zoneConfiguration = `
config system zone
    edit "USERS"
        set interface "port2" "port3"
    next
end
config firewall policy
    edit 1
        set srcintf "USERS"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
        set logtraffic all
    next
    edit 2
        set srcintf "port3"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
        set logtraffic all
    next
end`

    expect(analyzeConfiguration(zoneConfiguration).findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'shadowed', shadowedBy: '1' }),
    ]))
  })

  it('compare le contenu des schedules récurrents plutôt que leurs seuls noms', () => {
    const scheduleConfiguration = `
config firewall schedule recurring
    edit "BUSINESS-HOURS"
        set day monday tuesday wednesday thursday friday
        set start 08:00
        set end 18:00
    next
    edit "COPIE-HOURS"
        set day monday tuesday wednesday thursday friday
        set start 08:00
        set end 18:00
    next
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "BUSINESS-HOURS"
        set service "HTTPS"
        set logtraffic all
    next
    edit 2
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "COPIE-HOURS"
        set service "HTTPS"
        set logtraffic all
    next
end`

    expect(analyzeConfiguration(scheduleConfiguration).findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'duplicate', duplicateOf: '1' }),
    ]))
  })

  it('compare le contenu des schedules ponctuels', () => {
    const scheduleConfiguration = `
config firewall schedule onetime
    edit "MAINTENANCE-A"
        set start "2026/09/20 08:00"
        set end "2026/09/20 18:00"
    next
    edit "MAINTENANCE-B"
        set start "2026/09/20 08:00"
        set end "2026/09/20 18:00"
    next
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "MAINTENANCE-A"
        set service "HTTPS"
        set logtraffic all
    next
    edit 2
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "MAINTENANCE-B"
        set service "HTTPS"
        set logtraffic all
    next
end`

    expect(analyzeConfiguration(scheduleConfiguration).findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'duplicate', duplicateOf: '1' }),
    ]))
  })

  it('intègre les utilisateurs et groupes sources dans la couverture', () => {
    const userConfiguration = `
config user group
    edit "Employees"
        set member "alice"
    next
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set groups "Employees"
        set action accept
        set service "HTTPS"
        set logtraffic all
    next
    edit 2
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set users "bob"
        set action accept
        set service "HTTPS"
        set logtraffic all
    next
    edit 3
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set users "alice"
        set action accept
        set service "HTTPS"
        set logtraffic all
    next
end`

    const findings = analyzeConfiguration(userConfiguration).findings
    expect(findings).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'duplicate' }),
    ]))
    expect(findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '3', category: 'duplicate', duplicateOf: '1' }),
    ]))
  })

  it('ne confond pas deux politiques basées sur des Internet Services différents', () => {
    const internetServiceConfiguration = `
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set action accept
        set internet-service enable
        set internet-service-name "Microsoft-Office365"
        set logtraffic all
    next
    edit 2
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set action accept
        set internet-service enable
        set internet-service-name "Google-Gmail"
        set logtraffic all
    next
    edit 3
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set action accept
        set internet-service enable
        set internet-service-name "Microsoft-Office365"
        set logtraffic all
    next
end`

    const findings = analyzeConfiguration(internetServiceConfiguration).findings
    expect(findings).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'duplicate' }),
    ]))
    expect(findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '3', category: 'duplicate', duplicateOf: '1' }),
    ]))
  })

  it('signale les objets d’adresses dynamiques sans conclure à une équivalence', () => {
    const dynamicConfiguration = `
config firewall address
    edit "FQDN-APP"
        set type fqdn
        set fqdn "app.example.com"
    next
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "FQDN-APP"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
        set logtraffic all
    next
    edit 2
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "FQDN-APP"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
        set logtraffic all
    next
end`

    const findings = analyzeConfiguration(dynamicConfiguration).findings
    expect(findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '1', category: 'indeterminate' }),
      expect.objectContaining({ policyId: '2', category: 'indeterminate' }),
    ]))
    expect(findings).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'duplicate' }),
    ]))
  })

  it('signale les règles temporaires expirées ou sans expiration', () => {
    const temporaryConfiguration = `
config firewall policy
    edit 1
        set name "Accès temporaire expiré"
        set comments "temporary ticket CHG-1 owner SecOps"
        set expiration "2020/01/01"
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "Postes"
        set dstaddr "Serveur"
        set action accept
        set service "HTTPS"
        set logtraffic all
    next
    edit 2
        set name "Accès temporaire sans date"
        set comments "temporary"
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "Postes"
        set dstaddr "Serveur"
        set action accept
        set service "HTTPS"
        set logtraffic all
    next
end`

    const findings = analyzeConfiguration(temporaryConfiguration).findings
    expect(findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '1', category: 'temporary', severity: 'high' }),
      expect.objectContaining({ policyId: '2', category: 'temporary', detail: expect.stringContaining('date d’expiration') }),
    ]))
  })

  it('signale no-inspection et les profils UTM non identifiés', () => {
    const securityConfiguration = `
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "Postes"
        set dstaddr "Internet"
        set action accept
        set service "HTTPS"
        set utm-status enable
        set ssl-ssh-profile "no-inspection"
        set logtraffic all
    next
end`

    const findings = analyzeConfiguration(securityConfiguration).findings
    expect(findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '1', category: 'security' }),
      expect.objectContaining({ policyId: '1', category: 'inspection' }),
    ]))
  })

  it('signale les objets vides et non référencés', () => {
    const objectConfiguration = `
config firewall address
    edit "UNUSED-HOST"
        set subnet 192.0.2.10 255.255.255.255
    next
    edit "EMPTY-HOST"
    next
end
config firewall service custom
    edit "EMPTY-SERVICE"
    next
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
        set logtraffic all
    next
end`

    const findings = analyzeConfiguration(objectConfiguration).findings
    expect(findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: 'object:address:UNUSED-HOST', category: 'object' }),
      expect.objectContaining({ policyId: 'object:address:EMPTY-HOST', category: 'object' }),
      expect.objectContaining({ policyId: 'object:service:EMPTY-SERVICE', category: 'object' }),
    ]))
  })

  it('ne signale pas comme inutilisé un objet membre d\u2019un groupe référencé', () => {
    const configuration = `
config firewall address
    edit "SRV-A"
        set subnet 192.0.2.10 255.255.255.255
    next
    edit "SRV-B"
        set subnet 192.0.2.11 255.255.255.255
    next
end
config firewall addrgrp
    edit "GRP-INNER"
        set member "SRV-A"
    next
    edit "GRP-OUTER"
        set member "GRP-INNER" "SRV-B"
    next
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "GRP-OUTER"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
        set logtraffic all
    next
end`

    const objects = analyzeConfiguration(configuration).findings.filter((finding) => finding.category === 'object')
    expect(objects).toEqual([])
  })

  it('signale les objets en doublon sous des noms différents', () => {
    const configuration = `
config firewall address
    edit "WEB-1"
        set subnet 192.0.2.10 255.255.255.255
        set comment "primaire"
    next
    edit "WEB-1-COPIE"
        set subnet 192.0.2.10 255.255.255.255
    next
end
config firewall service custom
    edit "APP-8443"
        set tcp-portrange 8443
    next
    edit "APP-8443-BIS"
        set tcp-portrange 8443
    next
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "WEB-1" "WEB-1-COPIE"
        set dstaddr "all"
        set action accept
        set service "APP-8443" "APP-8443-BIS"
        set logtraffic all
    next
end`

    const findings = analyzeConfiguration(configuration).findings
    expect(findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: 'object:address:WEB-1-COPIE', title: 'Objet en doublon' }),
      expect.objectContaining({ policyId: 'object:service:APP-8443-BIS', title: 'Objet en doublon' }),
    ]))
    expect(findings.filter((finding) => finding.title === 'Objet en doublon')).toHaveLength(2)
  })

  it('signale une policy accept sans aucun profil de sécurité et accepte un profile-group', () => {
    const configuration = `
config firewall profile-group
    edit "PG-STANDARD"
        set av-profile "default"
        set ips-sensor "default"
        set webfilter-profile "default"
        set ssl-ssh-profile "certificate-inspection"
    next
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "LAN-NET"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
        set logtraffic all
    next
    edit 2
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "DMZ-NET"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
        set utm-status enable
        set profile-type group
        set profile-group "PG-STANDARD"
        set logtraffic all
    next
    edit 3
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "GUEST-NET"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
        set utm-status enable
        set ips-sensor "default"
        set logtraffic all
    next
end`

    const security = analyzeConfiguration(configuration).findings.filter((finding) => finding.category === 'security')
    expect(security).toHaveLength(2)
    expect(security).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '1', title: 'Aucun profil de sécurité', severity: 'medium' }),
      expect.objectContaining({ policyId: '3', title: 'Profils de sécurité incomplets', severity: 'low' }),
    ]))
  })

  it('identifie une VIP exposée à toutes les sources et conserve le contexte NAT', () => {
    const natConfiguration = `
config firewall vip
    edit "VIP-WEB"
        set extip 203.0.113.10
        set mappedip "10.0.0.10"
    next
end
config firewall policy
    edit 50
        set name "Publication web"
        set srcintf "wan"
        set dstintf "dmz"
        set srcaddr "all"
        set dstaddr "VIP-WEB"
        set action accept
        set service "HTTPS"
        set logtraffic all
    next
    edit 60
        set name "SaaS Microsoft"
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "Postes"
        set internet-service enable
        set internet-service-name "Microsoft-Office365"
        set action accept
        set nat enable
        set ippool enable
        set poolname "POOL-SORTANT"
        set logtraffic all
    next
end`

    const result = analyzeConfiguration(natConfiguration)

    expect(result.policies).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: '50', destinationVips: ['VIP-WEB'] }),
      expect.objectContaining({
        id: '60',
        internetServices: ['Microsoft-Office365'],
        ipPools: ['POOL-SORTANT'],
      }),
    ]))
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '50', category: 'exposure' }),
    ]))
  })

  it('signale une règle active sans usage récent quand les statistiques sont disponibles', () => {
    const result = analyzePolicies([{
      id: '7', order: 1, name: 'Ancienne règle', family: 'ipv4',
      srcintf: ['lan'], dstintf: ['wan'], srcaddr: ['Postes'], dstaddr: ['Serveur'],
      service: ['HTTPS'], schedule: ['always'], action: 'accept', status: 'enable',
      nat: 'disable', utmStatus: 'enable', logtraffic: 'all', comments: '',
      destinationVips: [], internetServices: [], ipPools: [], hitCount: 0,
      lastUsed: '2024-01-01 00:00:00',
    }])

    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '7', category: 'unused', severity: 'medium' }),
    ]))
    expect(result.stats.unused).toBe(1)
  })
})