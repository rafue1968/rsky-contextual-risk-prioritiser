module.exports = [
"[externals]/next/dist/compiled/next-server/app-route-turbo.runtime.dev.js [external] (next/dist/compiled/next-server/app-route-turbo.runtime.dev.js, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("next/dist/compiled/next-server/app-route-turbo.runtime.dev.js", () => require("next/dist/compiled/next-server/app-route-turbo.runtime.dev.js"));

module.exports = mod;
}),
"[externals]/next/dist/compiled/@opentelemetry/api [external] (next/dist/compiled/@opentelemetry/api, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("next/dist/compiled/@opentelemetry/api", () => require("next/dist/compiled/@opentelemetry/api"));

module.exports = mod;
}),
"[externals]/next/dist/compiled/next-server/app-page-turbo.runtime.dev.js [external] (next/dist/compiled/next-server/app-page-turbo.runtime.dev.js, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("next/dist/compiled/next-server/app-page-turbo.runtime.dev.js", () => require("next/dist/compiled/next-server/app-page-turbo.runtime.dev.js"));

module.exports = mod;
}),
"[externals]/next/dist/server/app-render/work-unit-async-storage.external.js [external] (next/dist/server/app-render/work-unit-async-storage.external.js, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("next/dist/server/app-render/work-unit-async-storage.external.js", () => require("next/dist/server/app-render/work-unit-async-storage.external.js"));

module.exports = mod;
}),
"[externals]/next/dist/server/app-render/work-async-storage.external.js [external] (next/dist/server/app-render/work-async-storage.external.js, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("next/dist/server/app-render/work-async-storage.external.js", () => require("next/dist/server/app-render/work-async-storage.external.js"));

module.exports = mod;
}),
"[externals]/next/dist/shared/lib/no-fallback-error.external.js [external] (next/dist/shared/lib/no-fallback-error.external.js, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("next/dist/shared/lib/no-fallback-error.external.js", () => require("next/dist/shared/lib/no-fallback-error.external.js"));

module.exports = mod;
}),
"[externals]/next/dist/server/app-render/after-task-async-storage.external.js [external] (next/dist/server/app-render/after-task-async-storage.external.js, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("next/dist/server/app-render/after-task-async-storage.external.js", () => require("next/dist/server/app-render/after-task-async-storage.external.js"));

module.exports = mod;
}),
"[project]/Desktop/rsky/apps/web/app/api/test-finding/route.ts [app-route] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "GET",
    ()=>GET
]);
var __TURBOPACK__imported__module__$5b$project$5d2f$Desktop$2f$rsky$2f$apps$2f$web$2f$node_modules$2f$next$2f$server$2e$js__$5b$app$2d$route$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/Desktop/rsky/apps/web/node_modules/next/server.js [app-route] (ecmascript)");
(()=>{
    const e = new Error("Cannot find module './lib/db/findings'");
    e.code = 'MODULE_NOT_FOUND';
    throw e;
})();
;
;
async function GET() {
    try {
        const finding = await createFinding({
            finding_id: crypto.randomUUID(),
            source: {
                scanner: "zap",
                scanner_version: "2.15",
                scan_id: "scan-001",
                scan_timestamp: new Date().toISOString()
            },
            vulnerability: {
                title: "SQL Injection",
                description: "Test finding",
                category: "web",
                cwe_ids: [
                    89
                ],
                cve_ids: [],
                references: []
            },
            severity: {
                level: "high",
                cvss_score: 8.8,
                cvss_vector: "AV:N/AC:L",
                confidence: "high"
            },
            target: {
                host: "example.com",
                port: 443,
                protocol: "https",
                url: "https://example.com",
                asset_type: "web_app"
            },
            evidence: {
                request: null,
                response: null,
                matched_content: null,
                parameter: null,
                attack_vector: null
            },
            remediation: {
                solution: "Patch application",
                solution_type: "vendorfix"
            },
            metadata: {
                raw_plugin_id: "1001",
                tags: [
                    "sqli"
                ],
                first_seen: new Date().toISOString(),
                raw_source_data: {}
            }
        });
        return __TURBOPACK__imported__module__$5b$project$5d2f$Desktop$2f$rsky$2f$apps$2f$web$2f$node_modules$2f$next$2f$server$2e$js__$5b$app$2d$route$5d$__$28$ecmascript$29$__["NextResponse"].json({
            success: true,
            finding
        });
    } catch (error) {
        console.error(error);
        return __TURBOPACK__imported__module__$5b$project$5d2f$Desktop$2f$rsky$2f$apps$2f$web$2f$node_modules$2f$next$2f$server$2e$js__$5b$app$2d$route$5d$__$28$ecmascript$29$__["NextResponse"].json({
            success: false,
            error
        }, {
            status: 500
        });
    }
}
}),
];

//# sourceMappingURL=%5Broot-of-the-server%5D__11~m1ow._.js.map