// Form submission handler for the security check
document.getElementById("check-form").addEventListener("submit", async (e) => {
    e.preventDefault(); // Prevent form submission

    const urlInput = document.getElementById("url").value; // Get the URL input
    const resultElement = document.getElementById("result"); // Security scan result element
    const domainCountElement = document.getElementById("domain-count"); // Number of domains
    const domainDetailsElement = document.getElementById("domain-details"); // Domain details list
    const showDetailsButton = document.getElementById("show-details-btn"); // Button to toggle domain details

    // TLS-related elements
    const tlsAnalyzerElement = document.getElementById("tls-analyzer");
    const tlsGradeElement = document.getElementById("tls-grade");
    const tlsLetterGradeElement = document.getElementById("tls-lettergrade");

    // Reset and show loading states
    resultElement.textContent = "Loading...";
    domainCountElement.textContent = "Number of domains: 0";
    domainDetailsElement.innerHTML = "";
    showDetailsButton.style.display = "none";
    domainDetailsElement.style.display = "none";

    tlsAnalyzerElement.textContent = "Loading...";
    tlsGradeElement.textContent = "Loading...";
    tlsLetterGradeElement.textContent = "Loading...";

    try {
        // Perform the security scan
        const scanResponse = fetch(`/api/scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: urlInput }),
        });

        // Fetch domain data from crt.sh
        const domainResponse = fetch(`/api/domains`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ domain: new URL(urlInput).hostname }),
        });

        // Fetch TLS information
        const tlsResponse = fetch(`/api/tls`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: urlInput }),
        });

        // Await all responses simultaneously
        const [scanData, domainData, tlsData] = await Promise.all([
            (await scanResponse).json(),
            (await domainResponse).json(),
            (await tlsResponse).json(),
        ]);

        // Display security scan result
        resultElement.textContent = JSON.stringify(scanData, null, 2);

        // Display domain data
        domainCountElement.textContent = `Number of domains: ${domainData.count}`;
        if (domainData.domains && domainData.domains.length > 0) {
            domainData.domains.forEach((domain) => {
                const li = document.createElement("li");
                li.textContent = domain;
                domainDetailsElement.appendChild(li);
            });
            showDetailsButton.style.display = "block"; // Show the button if domains are available
        }

        // Display TLS information
        if (tlsData.grade !== undefined && tlsData.lettergrade !== undefined) {
            tlsAnalyzerElement.textContent = "mozillaGradingWorker"; // Static as it's tied to the specific analyzer
            tlsGradeElement.textContent = tlsData.grade;
            tlsLetterGradeElement.textContent = tlsData.lettergrade;
        } else {
            tlsAnalyzerElement.textContent = "Analyzer data not available.";
            tlsGradeElement.textContent = "Grade data not available.";
            tlsLetterGradeElement.textContent = "Letter grade data not available.";
        }
    } catch (error) {
        // Handle errors for each request
        resultElement.textContent = `Error: ${error.message}`;
        domainCountElement.textContent = "N/A";
        tlsAnalyzerElement.textContent = `Error: ${error.message}`;
        tlsGradeElement.textContent = "N/A";
        tlsLetterGradeElement.textContent = "N/A";
    }
});

// Toggle domain details visibility
document.getElementById("show-details-btn").addEventListener("click", () => {
    const domainDetailsElement = document.getElementById("domain-details");
    domainDetailsElement.style.display = domainDetailsElement.style.display === "none" ? "block" : "none";
});

// WHOIS information fetch and toggle visibility
document.getElementById("whois-btn").addEventListener("click", async () => {
    const urlInput = document.getElementById("url").value; // Get the URL input
    const whoisResultElement = document.getElementById("whois-result"); // WHOIS result element

    // Check current visibility and toggle it
    if (whoisResultElement.style.display === "none") {
        whoisResultElement.style.display = "block"; // Show the WHOIS data
        whoisResultElement.textContent = "Loading WHOIS data...";

        try {
            const domain = new URL(urlInput).hostname; // Extract domain from URL
            const response = await fetch(`/api/whois`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ domain }),
            });

            if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
            const whoisData = await response.json();
            whoisResultElement.textContent = JSON.stringify(whoisData, null, 2);
        } catch (error) {
            whoisResultElement.textContent = `Error: ${error.message}`;
        }
    } else {
        // Hide the WHOIS data
        whoisResultElement.style.display = "none";
    }
});