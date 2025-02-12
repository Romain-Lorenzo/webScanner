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

    // Server-related elements
    const serverIpElement = document.getElementById("server-ip");
    const serverCityElement = document.getElementById("server-city");
    const serverCountryNameElement = document.getElementById("server-country-name");
    const serverContinentElement = document.getElementById("server-continent-name");  
    const serverCurrencyNameElement = document.getElementById("server-currency-name");

    // Security check elements
    const securityScoreElement = document.getElementById("security-score");
    const securityDetailsElement = document.getElementById("security-details");
    const toggleSecurityDetailsBtn = document.getElementById("toggle-security-details")

    //Loading animation
    const loadingAnimation = document.querySelector("#scan-wait");

    // Reset and show loading states
    resultElement.textContent = "Loading...";
    domainCountElement.textContent = "Number of domains: 0";
    domainDetailsElement.innerHTML = "";
    showDetailsButton.style.display = "none";
    domainDetailsElement.style.display = "none";

    tlsAnalyzerElement.textContent = "Loading...";
    tlsGradeElement.textContent = "Loading...";
    tlsLetterGradeElement.textContent = "Loading...";

    serverIpElement.textContent = "Loading...";
    serverCityElement.textContent = "Loading...";
    serverCountryNameElement.textContent = "Loading...";
    serverContinentElement.textContent = "Loading...";;
    serverCurrencyNameElement.textContent = "Loading...";

    securityScoreElement.textContent = "Loading...";
    securityDetailsElement.innerHTML = "";
    securityDetailsElement.style.display = "none";
    toggleSecurityDetailsBtn.style.display = "none";

     // Show Lottie animation
     loadingAnimation.classList.remove("hidden");

    try {
        // Perform all API queries simultaneously
        const scanResponse = fetch(`https://scanner.bunkerstaging.com/api/scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: urlInput }),
        });

        const domainResponse = fetch(`https://scanner.bunkerstaging.com/api/domains`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ domain: new URL(urlInput).hostname }),
        });

        const tlsResponse = fetch(`https://scanner.bunkerstaging.com/api/tls`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: urlInput }),
        });

        const serverInfoResponse = fetch(`https://scanner.bunkerstaging.com/api/server-info`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: urlInput }),
        });

        const securityResponse = fetch(`https://scanner.bunkerstaging.com/api/security`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: urlInput }),
        });

        // Await all responses
        const [scanData, domainData, tlsData, serverInfoData, securityData] = await Promise.all([
            (await scanResponse).json(),
            (await domainResponse).json(),
            (await tlsResponse).json(),
            (await serverInfoResponse).json(),
            (await securityResponse).json(),
        ]);

        // Modify JSON response: Change "hasWaf" to visual format
        if (scanData.hasOwnProperty("hasWaf")) {
            scanData.wafStatus = scanData.hasWaf
                ? "<span style='color:green; font-weight:bold;'>✅</span>"
                : "<span style='color:red; font-weight:bold;'>❌</span>";
        }

        // Display security scan result
        resultElement.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center; font-size: 1.5em;">
                <span>WAF</span>
                ${scanData.wafStatus} 
            </div>
        `;

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

        // Display server info
        if (serverInfoData) {
            serverIpElement.textContent = serverInfoData.ipAddress || "N/A";
            serverCityElement.textContent = serverInfoData.cityName || "N/A";
            serverCountryNameElement.textContent = serverInfoData.countryName || "N/A";
            serverContinentElement.textContent = serverInfoData.continent || "N/A";
            serverCurrencyNameElement.textContent = serverInfoData.currency?.name || "N/A";
        } else {
            resultElement.textContent = "Server info not available.";
        }
    
        // Display security score and details
        if (securityData && securityData.score) {
            securityScoreElement.textContent = `${securityData.score}`;
            securityDetailsElement.textContent = JSON.stringify(securityData.report, null, 2);
            toggleSecurityDetailsBtn.style.display = "block"; // Show button
        } else {
            securityScoreElement.textContent = "Security data not available.";
        }

         // Introduce a 3-4 second delay before showing the results
         setTimeout(() => {
            document.querySelectorAll(".hidden").forEach(el => el.classList.remove("hidden"));
            loadingAnimation.classList.add("hidden"); // Hide Lottie animation
        }, 4000); // Adjust delay time in milliseconds (4000ms = 4 seconds)

    } catch (error) {
        // Handle errors for all requests
        resultElement.textContent = `Error: ${error.message}`;
        domainCountElement.textContent = "N/A";
        tlsAnalyzerElement.textContent = `Error: ${error.message}`;
        tlsGradeElement.textContent = "N/A";
        tlsLetterGradeElement.textContent = "N/A";
        serverIpElement.textContent = "Error fetching IP data.";
        serverCityElement.textContent = "N/A";
        serverCountryNameElement.textContent = "N/A";
        serverContinentElement.textContent = "N/A";
        serverCurrencyNameElement.textContent = "N/A";
        securityScoreElement.textContent = "Error fetching security data.";
        securityDetailsElement.textContent = "N/A";
        loadingAnimation.classList.add("hidden"); // Hide animation on error
    }
});

// Toggle domain details visibility
document.getElementById("show-details-btn").addEventListener("click", () => {
    const domainDetailsElement = document.getElementById("domain-details");
    domainDetailsElement.style.display = domainDetailsElement.style.display === "none" ? "block" : "none";
});

// Toggle security details visibility
document.getElementById("toggle-security-details").addEventListener("click", () => {
    const securityDetailsElement = document.getElementById("security-details");
    securityDetailsElement.style.display = securityDetailsElement.style.display === "none" ? "block" : "none";
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
            const response = await fetch(`https://scanner.bunkerstaging.com/api/whois`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ domain }),
            });

            if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
            const whoisData = await response.json();
            // Extract only the required fields
            const relevantData = {
                "Creation Date": whoisData.internicData.Creation_Date,
                "DNSSEC": whoisData.internicData.DNSSEC,
                "DNSSEC DS Data": whoisData.internicData.DNSSEC_DS_Data,
                "Domain Name": whoisData.internicData.Domain_Name,
                "Domain Status": whoisData.internicData.Domain_Status,
                "Name Server": whoisData.internicData.Name_Server,
                "Registrar": whoisData.internicData.Registrar,
                "Registrar IANA ID": whoisData.internicData.Registrar_IANA_ID,
                "Registrar URL": whoisData.internicData.Registrar_URL,
                "Registrar WHOIS Server": whoisData.internicData.Registrar_WHOIS_Server,
                "Registry Domain ID": whoisData.internicData.Registry_Domain_ID,
                "Registry Expiry Date": whoisData.internicData.Registry_Expiry_Date,
                "ICANN Whois Complaint Form": whoisData.internicData.URL_of_the_ICANN_Whois_Inaccuracy_Complaint_Form,
                "Updated Date": whoisData.internicData.Updated_Date,
                "Last Update of Whois Database": whoisData.internicData._Last_update_of_whois_database
            };

            // Convert to formatted HTML output
            let formattedHtml = "<ul>";
            for (const [key, value] of Object.entries(relevantData)) {
                formattedHtml += `<li><strong>${key}:</strong> ${value}</li>`;
            }
            formattedHtml += "</ul>";

            // Display the formatted data
            whoisResultElement.innerHTML = formattedHtml;

        } catch (error) {
            whoisResultElement.textContent = `Error: ${error.message}`;
        }
    } else {
        // Hide the WHOIS data
        whoisResultElement.style.display = "none";
    }
});