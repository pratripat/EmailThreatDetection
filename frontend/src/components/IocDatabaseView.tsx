import React, { useState } from 'react';
import { Search, Database } from 'lucide-react';

interface IocRecord {
  id: string;
  type: 'IP' | 'DOMAIN' | 'URL' | 'EMAIL' | 'HASH';
  value: string;
  threatCategory: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  firstSeen: string;
  associatedCase: string;
}

const SAMPLE_IOCS: IocRecord[] = [
  { id: 'ioc-101', type: 'IP', value: '198.51.100.1', threatCategory: 'Tor Exit Node / Phishing Relay', severity: 'CRITICAL', firstSeen: '2026-07-12', associatedCase: '#EML-2026-00421' },
  { id: 'ioc-102', type: 'DOMAIN', value: 'paypa1-support.com', threatCategory: 'Brand Impersonation / Typosquat', severity: 'CRITICAL', firstSeen: '2026-08-01', associatedCase: '#EML-2026-00421' },
  { id: 'ioc-103', type: 'URL', value: 'https://paypal-secure-login.xyz/auth/verify', threatCategory: 'Credential Harvester Page', severity: 'CRITICAL', firstSeen: '2026-08-02', associatedCase: '#EML-2026-00421' },
  { id: 'ioc-104', type: 'EMAIL', value: 'security@paypa1-support.com', threatCategory: 'Phishing Sender Header', severity: 'HIGH', firstSeen: '2026-08-02', associatedCase: '#EML-2026-00421' },
  { id: 'ioc-105', type: 'IP', value: '194.38.20.12', threatCategory: 'Bulletproof Hosting MTA', severity: 'HIGH', firstSeen: '2026-08-10', associatedCase: '#EML-2026-00392' },
  { id: 'ioc-106', type: 'DOMAIN', value: 'enterprise-global-corp.top', threatCategory: 'BEC Executive Fraud Domain', severity: 'CRITICAL', firstSeen: '2026-08-15', associatedCase: '#EML-2026-00392' },
  { id: 'ioc-107', type: 'IP', value: '91.240.118.5', threatCategory: 'Malware Ingress Relay', severity: 'HIGH', firstSeen: '2026-08-18', associatedCase: '#EML-2026-00388' },
];

export const IocDatabaseView: React.FC = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<string>('ALL');

  const filtered = SAMPLE_IOCS.filter((item) => {
    const matchSearch = item.value.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.threatCategory.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.associatedCase.toLowerCase().includes(searchTerm.toLowerCase());
    const matchType = filterType === 'ALL' || item.type === filterType;
    return matchSearch && matchType;
  });

  return (
    <div className="forensic-subcard full-width">
      <div className="subcard-title-bar">
        <div className="flex items-center gap-2">
          <Database size={16} className="text-cyan" />
          <span className="subcard-title">INDICATORS OF COMPROMISE (IOC) REGISTRY</span>
        </div>

        <div className="ioc-filter-controls">
          <div className="search-box-minimal">
            <Search size={14} className="text-muted" />
            <input
              type="text"
              placeholder="Search IOCs, IPs, domains..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="search-input-clean"
            />
          </div>

          <select 
            value={filterType} 
            onChange={(e) => setFilterType(e.target.value)}
            className="filter-select-minimal"
          >
            <option value="ALL">All Indicator Types</option>
            <option value="IP">IP Addresses</option>
            <option value="DOMAIN">Domains</option>
            <option value="URL">URLs</option>
            <option value="EMAIL">Emails</option>
          </select>
        </div>
      </div>

      <div className="ioc-registry-table-wrapper">
        <table className="minimal-table font-mono">
          <thead>
            <tr>
              <th>INDICATOR VALUE</th>
              <th>TYPE</th>
              <th>THREAT CATEGORY</th>
              <th>SEVERITY</th>
              <th>FIRST SEEN</th>
              <th>CASE REF</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((ioc) => (
              <tr key={ioc.id}>
                <td className="font-bold text-white">{ioc.value}</td>
                <td>
                  <span className="ioc-type-pill">{ioc.type}</span>
                </td>
                <td className="text-muted">{ioc.threatCategory}</td>
                <td>
                  <span className={`ioc-severity-pill ${ioc.severity.toLowerCase()}`}>
                    {ioc.severity}
                  </span>
                </td>
                <td className="text-muted">{ioc.firstSeen}</td>
                <td className="text-cyan">{ioc.associatedCase}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
