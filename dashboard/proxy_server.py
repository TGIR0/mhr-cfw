    # ── Dashboard status page ─────────────────────────────────
    async def _handle_dashboard(self, writer):
        from smart_router import CloudflareDetector, DependencyResolver
        detector = CloudflareDetector()

        cache_stats = self._cache.hits, self._cache.misses

        html = """
        <!DOCTYPE html>
        <html lang="fa" dir="rtl">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>MHR Dashboard</title>
            <style>
                * { box-sizing: border-box; margin: 0; padding: 0; }
                body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }
                .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1.5rem; margin-bottom: 1rem; }
                h1 { color: #58a6ff; margin-bottom: 1rem; }
                .stat { display: inline-block; margin: 0 1rem 1rem 0; }
                .stat span { color: #8b949e; }
                .stat strong { color: #f0f6fc; }
                .ok { color: #3fb950; }
                .warn { color: #d29922; }
                .err { color: #f85149; }
                table { width: 100%%; border-collapse: collapse; margin: 1rem 0; }
                th, td { border: 1px solid #30363d; padding: 0.5rem; text-align: center; }
                th { background: #21262d; }
                tr:hover { background: #1c2128; }
            </style>
        </head>
        <body>
            <h1>🚀 MHR Dashboard</h1>
            <div class="card">
                <div class="stat"><span>HTTP پروکسی:</span> <strong>127.0.0.1:%s</strong></div>
                <div class="stat"><span>SOCKS5:</span> <strong>127.0.0.1:%s</strong></div>
                <div class="stat"><span>Cache:</span> <strong>%d زنده / %d خطا</strong></div>
                <div class="stat"><span>SNI فعال:</span> <strong>%s</strong></div>
            </div>
            <div class="card">
                <h2>📡 Dependency Resolver</h2>
                <table>
                    <tr><th>Parent Domain</th><th>Dependencies</th></tr>
        """ % (self.port, self.socks_port, cache_stats[0], cache_stats[1], self.fronter.sni_host)

        from domain_map import DOMAIN_DEPENDENCIES
        for domain, deps in list(DOMAIN_DEPENDENCIES.items())[:10]:
            html += f"<tr><td>{domain}</td><td>{', '.join(deps[:4])}</td></tr>"

        html += """
                </table>
                <p style="color:#8b949e;font-size:0.9rem;margin-top:1rem;">طراحی این صفحه توسط شما تکمیل خواهد شد.</p>
            </div>
        </body>
        </html>
        """

        writer.write(f"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {len(html)}\r\n\r\n{html}".encode())
        await writer.drain()