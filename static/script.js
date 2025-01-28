document.getElementById("check-form").addEventListener("submit", async (e) => {
    e.preventDefault(); // Prevent form submission
    const urlInput = document.getElementById("url").value; // Get the URL input
    const resultElement = document.getElementById("result"); // Get the result element
    resultElement.textContent = "Loading..."; // Show a loading message

    try {
        const response = await fetch(`/api/scan`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: urlInput }),
        });

        if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`); // Handle HTTP errors
        const data = await response.json(); // Parse the response JSON
        resultElement.textContent = JSON.stringify(data, null, 2); // Display the result in a readable format
    } catch (error) {
        resultElement.textContent = `Error: ${error.message}`; // Display the error message
    }
});
