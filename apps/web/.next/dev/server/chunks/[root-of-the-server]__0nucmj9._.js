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
"[project]/Desktop/rsky/apps/web/lib/supabase/client.ts [app-route] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "supabase",
    ()=>supabase
]);
(()=>{
    const e = new Error("Cannot find module '@supabase/supabase-js'");
    e.code = 'MODULE_NOT_FOUND';
    throw e;
})();
;
const supabaseUrl = "https://aanyymkdmiagbqwbhlcc.supabase.co";
const supabaseAnonKey = ("TURBOPACK compile-time value", "sb_publishable_hIjqpR5YDSKS2s8DhJiZ0w_uEv3Hz3b");
const supabase = createClient(supabaseUrl, supabaseAnonKey);
}),
"[project]/Desktop/rsky/apps/web/lib/db/finding.ts [app-route] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "createFinding",
    ()=>createFinding,
    "getFindingById",
    ()=>getFindingById,
    "getFindings",
    ()=>getFindings
]);
// lib/db/findings.ts
var __TURBOPACK__imported__module__$5b$project$5d2f$Desktop$2f$rsky$2f$apps$2f$web$2f$lib$2f$supabase$2f$client$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/Desktop/rsky/apps/web/lib/supabase/client.ts [app-route] (ecmascript)");
;
async function createFinding(finding) {
    const { data, error } = await __TURBOPACK__imported__module__$5b$project$5d2f$Desktop$2f$rsky$2f$apps$2f$web$2f$lib$2f$supabase$2f$client$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["supabase"].from('findings').insert(finding).select();
    if (error) {
        // DB-level failure (constraint, connection, etc.)
        throw new Error(error.message);
    }
    return data;
}
async function getFindings() {
    const { data, error } = await __TURBOPACK__imported__module__$5b$project$5d2f$Desktop$2f$rsky$2f$apps$2f$web$2f$lib$2f$supabase$2f$client$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["supabase"].from('findings').select('*');
    if (error) {
        throw new Error(error.message);
    }
    return data;
}
async function getFindingById(id) {
    const { data, error } = await __TURBOPACK__imported__module__$5b$project$5d2f$Desktop$2f$rsky$2f$apps$2f$web$2f$lib$2f$supabase$2f$client$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["supabase"].from('findings').select('*').eq('finding_id', id).single();
    if (error) {
        throw new Error(error.message);
    }
    return data;
} /**
 * Why this layer exists:
 * - isolates Supabase dependency
 * - makes future migration easier (e.g. Postgres → API → Kafka)
 * - keeps routes clean
 */ 
}),
"[project]/Desktop/rsky/apps/web/app/api/test-finding/route.ts [app-route] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "GET",
    ()=>GET
]);
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$server$2e$js__$5b$app$2d$route$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/server.js [app-route] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$Desktop$2f$rsky$2f$apps$2f$web$2f$lib$2f$db$2f$finding$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/Desktop/rsky/apps/web/lib/db/finding.ts [app-route] (ecmascript)");
;
;
async function GET() {
    const finding = await (0, __TURBOPACK__imported__module__$5b$project$5d2f$Desktop$2f$rsky$2f$apps$2f$web$2f$lib$2f$db$2f$finding$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["createFinding"])({
        finding_id: crypto.randomUUID(),
        source: {
            scanner: "zap",
            scanner_version: "2.15",
            scan_id: "scan-001",
            scan_timestamp: new Date().toISOString()
        },
        vulnerability: {
            title: "SQL Injection",
            description: "test",
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
            cvss_vector: "AV:N",
            confidence: "high"
        },
        target: {
            host: "example.com",
            port: 443,
            protocol: "https",
            url: "https://example.com",
            asset_type: "web_app"
        },
        evidence: {},
        remediation: {
            solution: "Patch",
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
    return __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$server$2e$js__$5b$app$2d$route$5d$__$28$ecmascript$29$__["NextResponse"].json({
        success: true,
        finding
    });
}
}),
];

//# sourceMappingURL=%5Broot-of-the-server%5D__0nucmj9._.js.map