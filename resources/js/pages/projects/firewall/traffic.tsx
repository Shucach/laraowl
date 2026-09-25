import { Head, usePage, router } from '@inertiajs/react';
import {
    Shield,
    Activity,
    Globe,
    User,
    Terminal,
    MapPin,
    ShieldAlert,
} from 'lucide-react';
import { AreaChart, Area, ResponsiveContainer } from 'recharts';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Icon } from '@/components/ui/icon';
import AppLayout from '@/layouts/app-layout';
import { ConnectCloudflare } from './components/connect-cloudflare';
import { FirewallNav } from './components/firewall-nav';

const Sparkline = ({ data, color }: { data: number[]; color: string }) => (
    <div className="h-6 w-16">
        <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data.map((v) => ({ v }))}>
                <Area
                    type="monotone"
                    dataKey="v"
                    stroke={color}
                    fill={color}
                    fillOpacity={0.1}
                    strokeWidth={1.5}
                />
            </AreaChart>
        </ResponsiveContainer>
    </div>
);

const StatCard = ({
    title,
    icon,
    items,
    color = '#3b82f6',
    onBlock,
}: {
    title: string;
    icon: any;
    items: any[];
    color?: string;
    onBlock?: (ip: string) => void;
}) => (
    <Card className="overflow-hidden border-border bg-card shadow-2xl">
        <CardHeader className="border-b border-border/50 p-4">
            <CardTitle className="flex items-center gap-2 text-[10px] font-black tracking-widest text-muted-foreground uppercase">
                <Icon iconNode={icon} className="size-3.5" />
                {title}
            </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
            <div className="divide-y divide-border/50">
                {items.length > 0 ? (
                    items.map((item, i) => (
                        <div
                            key={i}
                            className="group flex items-center justify-between p-4 transition-colors hover:bg-muted/30"
                        >
                            <div className="flex items-center gap-3 overflow-hidden">
                                {title === 'Top IPs' && (
                                    <div className="h-2 w-2 rounded-full bg-primary/20 transition-colors group-hover:bg-primary" />
                                )}
                                <span className="truncate font-mono text-[11px] font-bold text-foreground/90">
                                    {item.name}
                                </span>
                            </div>
                            <div className="flex items-center gap-4">
                                <span className="text-[11px] font-black text-foreground">
                                    {item.count.toLocaleString()}
                                </span>
                                <Sparkline data={item.trend} color={color} />
                                {title === 'Top IPs' && onBlock && (
                                    <Button
                                        variant="ghost"
                                        size="icon"
                                        onClick={() => onBlock(item.name)}
                                        className="h-7 w-7 text-muted-foreground opacity-0 transition-all group-hover:opacity-100 hover:text-red-500"
                                    >
                                        <ShieldAlert className="size-3.5" />
                                    </Button>
                                )}
                            </div>
                        </div>
                    ))
                ) : (
                    <div className="p-8 text-center text-xs font-medium text-muted-foreground">
                        No data available
                    </div>
                )}
            </div>
        </CardContent>
    </Card>
);

export default function FirewallTraffic({
    isConfigured,
    topIps,
    topUserAgents,
    topPaths,
    topAsNames,
    topCountries,
    topActions,
}: {
    isConfigured: boolean;
    topIps: any;
    topUserAgents: any;
    topPaths: any;
    topAsNames: any;
    topCountries: any;
    topActions: any;
}) {
    const { props }: any = usePage();
    const teamSlug = props.currentTeam?.slug || props.current_team?.slug;
    const projectSlug =
        props.currentProject?.slug || props.current_project?.slug;

    const blockIp = (ip: string) => {
        if (confirm(`Are you sure you want to block ${ip}?`)) {
            router.post(
                `/${teamSlug}/${projectSlug}/firewall/rules/ip`,
                {
                    ip: ip,
                    note: `Blocked from Traffic Analysis at ${new Date().toLocaleString()}`,
                },
                { preserveScroll: true },
            );
        }
    };

    return (
        <div>
            <Head title="Traffic Analysis" />

            <div className="animate-in space-y-8 duration-700 fade-in">
                <FirewallNav active="traffic" />

                {!isConfigured ? (
                    <ConnectCloudflare />
                ) : (
                    <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
                        <StatCard
                            title="Top IPs"
                            icon={Globe}
                            items={topIps}
                            onBlock={blockIp}
                        />
                        <StatCard
                            title="Top Countries"
                            icon={MapPin}
                            items={topCountries}
                            color="#10b981"
                        />
                        <StatCard
                            title="Top Actions"
                            icon={Shield}
                            items={topActions}
                            color="#ef4444"
                        />
                        <StatCard
                            title="Top AS Names"
                            icon={Activity}
                            items={topAsNames}
                            color="#8b5cf6"
                        />
                        <StatCard
                            title="Top User Agents"
                            icon={User}
                            items={topUserAgents}
                            color="#f59e0b"
                        />
                        <StatCard
                            title="Top Request Paths"
                            icon={Terminal}
                            items={topPaths}
                            color="#64748b"
                        />
                    </div>
                )}
            </div>
        </div>
    );
}

FirewallTraffic.layout = (page: any) => (
    <AppLayout
        children={page}
        breadcrumbs={[
            { title: 'Firewall', href: '#' },
            { title: 'Traffic', href: '#' },
        ]}
    />
);
