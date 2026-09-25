import { Link, usePage } from '@inertiajs/react';
import { Activity, Bot, Filter, LayoutGrid, List } from 'lucide-react';

export type FirewallTab =
    | 'overview'
    | 'traffic'
    | 'rules'
    | 'audit'
    | 'auto-attack-mode';

export function FirewallNav({ active }: { active: FirewallTab }) {
    const { props }: any = usePage();
    const teamSlug = props.currentTeam?.slug || props.current_team?.slug;
    const projectSlug =
        props.currentProject?.slug || props.current_project?.slug;
    const base = `/${teamSlug}/${projectSlug}/firewall`;

    const navItems = [
        { key: 'overview', title: 'Overview', href: base, icon: LayoutGrid },
        {
            key: 'traffic',
            title: 'Traffic',
            href: `${base}/traffic`,
            icon: Activity,
        },
        { key: 'rules', title: 'Rules', href: `${base}/rules`, icon: Filter },
        {
            key: 'auto-attack-mode',
            title: 'Auto Attack Mode',
            href: `${base}/auto-attack-mode`,
            icon: Bot,
        },
        { key: 'audit', title: 'Audit Log', href: `${base}/audit`, icon: List },
    ];

    return (
        <div className="flex items-center gap-1 overflow-x-auto border-b border-border/50 pb-4">
            {navItems.map((item) => (
                <Link
                    key={item.key}
                    href={item.href}
                    className={`flex shrink-0 items-center gap-2 rounded-lg px-4 py-2 text-xs font-bold transition-all ${
                        item.key === active
                            ? 'border border-primary/20 bg-primary/10 text-primary'
                            : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                    }`}
                >
                    <item.icon className="size-3.5" />
                    {item.title}
                </Link>
            ))}
        </div>
    );
}
