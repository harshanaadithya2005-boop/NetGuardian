/* Offline canvas fallback for the four analytics charts. Uses Chart.js when available. */
"use strict";
if (!window.Chart) {
    window.Chart = class {
        constructor(canvas, config) {
            this.canvas = canvas;
            this.data = config.data;
            this.type = config.type;
            this.update();
            window.addEventListener("resize", () => this.update());
        }
        update() {
            const canvas = this.canvas;
            const width = Math.max(300, canvas.parentElement.clientWidth - 30);
            const height = 280;
            canvas.width = width * devicePixelRatio;
            canvas.height = height * devicePixelRatio;
            canvas.style.width = "100%";
            canvas.style.height = `${height}px`;
            const ctx = canvas.getContext("2d");
            ctx.scale(devicePixelRatio, devicePixelRatio);
            ctx.font = "12px sans-serif";
            const values = this.data.datasets[0].data;
            const labels = this.data.labels;
            const colors = ["#38bdf8", "#a78bfa", "#f59e0b", "#34d399", "#94a3b8"];
            canvas.setAttribute("role", "img");
            canvas.setAttribute("aria-label", labels.map((label, i) => `${label}: ${values[i]}`).join(", ") || "No traffic recorded");
            ctx.fillStyle = "#cbd5e1";
            if (!values.length || values.every(x => Number(x) === 0)) {
                ctx.fillText("No data recorded yet", 20, 40);
                return;
            }
            if (this.type === "doughnut") {
                const total = values.reduce((a,b) => a+Number(b), 0);
                let angle = -Math.PI/2;
                values.forEach((value,i) => {
                    const end = angle + value/total*Math.PI*2;
                    ctx.beginPath(); ctx.arc(width/3, 125, 85, angle, end);
                    ctx.strokeStyle = colors[i%colors.length]; ctx.lineWidth = 32; ctx.stroke();
                    ctx.fillStyle = colors[i%colors.length];
                    ctx.fillText(`${labels[i]}: ${value}`, width*0.61, 35+i*22);
                    angle = end;
                });
                return;
            }
            const max = Math.max(1, ...values);
            const plotWidth = width-75;
            const step = plotWidth/Math.max(1,values.length);
            ctx.strokeStyle = "#475569";
            ctx.beginPath(); ctx.moveTo(55,20); ctx.lineTo(55,220); ctx.lineTo(width-10,220); ctx.stroke();
            ctx.fillStyle = "#cbd5e1"; ctx.fillText(String(max), 0, 22); ctx.fillText("0",30,220);
            if (this.type === "line") { ctx.beginPath(); ctx.strokeStyle = colors[0]; ctx.lineWidth=2; }
            values.forEach((value,i) => {
                const x = 55+step*(i+0.5);
                const y = 220-Number(value)/max*190;
                if (this.type === "line") { if (i) ctx.lineTo(x,y); else ctx.moveTo(x,y); }
                else {
                    ctx.fillStyle = colors[i%colors.length]; ctx.fillRect(x-step*0.3,y,step*0.6,220-y);
                    ctx.fillStyle = "#cbd5e1"; ctx.fillText(String(value),x-5,y-6);
                }
                if (i % Math.max(1,Math.ceil(labels.length/7)) === 0) {
                    ctx.fillStyle="#cbd5e1"; ctx.fillText(String(labels[i]),Math.max(55,x-30),245);
                }
            });
            if (this.type === "line") ctx.stroke();
        }
    };
}
