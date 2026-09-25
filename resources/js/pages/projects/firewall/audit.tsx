import { Head } from '@inertiajs/react';
import {
    List,
    Shield,
    Search,
    Clock,
    Globe,
    ShieldCheck,
    ShieldAlert,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import AppLayout from '@/layouts/app-layout';
import { ConnectCloudflare } from './components/connect-cloudflare';
import { FirewallNav } from './components/firewall-nav';

const ActionBadge = ({ action }: { action: string }) => {
    switch (action.toLowerCase()) {
        case 'block':
            return (
                <Badge className="gap-1.5 border-red-500/20 bg-red-500/10 text-[9px] font-black text-red-500 uppercase">
                    <ShieldAlert className="size-3" /> Blocked
                </Badge>
            );
        case 'challenge':
            return (
                <Badge className="gap-1.5 border-orange-500/20 bg-orange-500/10 text-[9px] font-black text-orange-500 uppercase">
                    <Shield className="size-3" /> Challenged
                </Badge>
            );
        case 'allow':
            return (
                <Badge className="gap-1.5 border-emerald-500/20 bg-emerald-500/10 text-[9px] font-black text-emerald-500 uppercase">
                    <ShieldCheck className="size-3" /> Allowed
                </Badge>
            );
        default:
            return (
                <Badge
                    variant="outline"
                    className="text-[9px] font-black uppercase"
                >
                    {action}
                </Badge>
            );
    }
};

export default function FirewallAudit({
    isConfigured,
    logs,
}: {
    isConfigured: boolean;
    logs: any[];
}) {
    return (
        <div>
            <Head title="Firewall Audit Log" />

            <div className="animate-in space-y-8 duration-700 fade-in">
                <FirewallNav active="audit" />

                {!isConfigured ? (
                    <ConnectCloudflare />
                ) : (
                    <div className="space-y-6">
                        <div className="flex items-center justify-between">
                            <div className="flex flex-col gap-1">
                                <h2 className="text-xl font-black tracking-tight text-foreground">
                                    Audit Log
                                </h2>
                                <p className="text-xs text-muted-foreground">
                                    Track manual and automated firewall actions.
                                </p>
                            </div>
                            <div className="relative w-64">
                                <Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
                                <Input
                                    placeholder="Search logs..."
                                    className="h-9 border-border bg-muted/50 pl-9 text-xs"
                                />
                            </div>
                        </div>

                        <Card className="overflow-hidden border-border bg-card shadow-xl">
                            <div className="overflow-x-auto">
                                <table className="w-full border-collapse text-left">
                                    <thead>
                                        <tr className="border-b border-border bg-muted/30">
                                            <th className="p-4 text-[10px] font-black tracking-widest text-muted-foreground uppercase">
                                                Action
                                            </th>
                                            <th className="p-4 text-[10px] font-black tracking-widest text-muted-foreground uppercase">
                                                Description
                                            </th>
                                            <th className="p-4 text-[10px] font-black tracking-widest text-muted-foreground uppercase">
                                                Target
                                            </th>
                                            <th className="p-4 text-[10px] font-black tracking-widest text-muted-foreground uppercase">
                                                Changed By
                                            </th>
                                            <th className="p-4 text-[10px] font-black tracking-widest text-muted-foreground uppercase">
                                                Date
                                            </th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-border">
                                        {logs.map((log) => (
                                            <tr
                                                key={log.id}
                                                className="group transition-colors hover:bg-muted/20"
                                            >
                                                <td className="p-4">
                                                    <ActionBadge
                                                        action={log.action}
                                                    />
                                                </td>
                                                <td className="p-4">
                                                    <span className="text-xs font-bold text-foreground">
                                                        {log.description}
                                                    </span>
                                                </td>
                                                <td className="p-4">
                                                    <div className="flex items-center gap-2">
                                                        <Globe className="size-3.5 text-muted-foreground" />
                                                        <code className="rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-[10px]">
                                                            {log.target}
                                                        </code>
                                                    </div>
                                                </td>
                                                <td className="p-4">
                                                    <div className="flex items-center gap-2">
                                                        <div className="flex size-6 items-center justify-center rounded-full border border-primary/20 bg-primary/10 text-[10px] font-black text-primary">
                                                            {log.user.charAt(0)}
                                                        </div>
                                                        <span className="text-xs font-medium text-foreground">
                                                            {log.user}
                                                        </span>
                                                    </div>
                                                </td>
                                                <td className="p-4">
                                                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                                                        <Clock className="size-3.5" />
                                                        {new Date(
                                                            log.created_at,
                                                        ).toLocaleString()}
                                                    </div>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </Card>

                        {logs.length === 0 && (
                            <div className="flex flex-col items-center justify-center space-y-4 py-24 text-center">
                                <div className="flex size-16 items-center justify-center rounded-full bg-muted">
                                    <List className="size-8 text-muted-foreground/30" />
                                </div>
                                <div className="space-y-1">
                                    <h3 className="text-lg font-black text-foreground">
                                        No logs found
                                    </h3>
                                    <p className="max-w-xs text-xs text-muted-foreground">
                                        There are no firewall events matching
                                        your current filters.
                                    </p>
                                </div>
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}

FirewallAudit.layout = (page: any) => (
    <AppLayout
        children={page}
        breadcrumbs={[
            { title: 'Firewall', href: '#' },
            { title: 'Audit Log', href: '#' },
        ]}
    />
);
