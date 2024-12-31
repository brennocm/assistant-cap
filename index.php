<?php
// Iniciar sessão com configurações seguras
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_strict_mode', 1);
ini_set('session.cookie_samesite', 'Strict');
session_start();

require_once 'includes/questions.php';

// Implementar proteção CSRF
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        http_response_code(403);
        exit('CSRF validation failed');
    }
}


// Validação e sanitização do parâmetro q
$currentQuestion = 1; // Valor padrão
if (isset($_GET['q'])) {
    $q = filter_input(INPUT_GET, 'q', FILTER_VALIDATE_INT);
    if (is_int($q) && $q >= 1 && $q <= 50) {
        $currentQuestion = $q;
    } else{
        http_response_code(400); // Bad request
        exit('Invalid question number');
    }
}

// Rate limiting
if (!isset($_SESSION['last_request'])) {
    $_SESSION['last_request'] = time();
    $_SESSION['request_count'] = 1;
} else {
    $time_diff = time() - $_SESSION['last_request'];
    if ($time_diff < 1) { // Limite de 1 requisição por segundo
        if ($_SESSION['request_count'] > 10) { // Máximo de 10 requisições rápidas
            http_response_code(429);
            exit('Too many requests');
        }
        $_SESSION['request_count']++;
    } else {
        $_SESSION['last_request'] = time();
        $_SESSION['request_count'] = 1;
    }
}

// Verificar se a questão existe antes de acessá-la
if (!isset($questions[$currentQuestion])) {
    http_response_code(404);
    exit("Question number {$currentQuestion} not found.");
}

$question = $questions[$currentQuestion];
    header("X-Content-Type-Options: nosniff");
    header("X-Frame-Options: DENY");
    header("X-XSS-Protection: 1; mode=block");
    header("Referrer-Policy: strict-origin-when-cross-origin");
    header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <link rel="stylesheet" href="assets/styles.css" type="text/css"/>
    <link rel="icon" type="image/x-icon" href="assets/images/ic.png">
    <script src="assets/js/jquery.min.js"></script>
    <title>CAP Assistant</title>
</head>
<body>
    <nav class="breadcrumb">
        <?php echo htmlspecialchars('Certified AppSec Practitioner (CAP) Assistant', ENT_QUOTES, 'UTF-8'); ?>
    </nav>
    <main class="quiz-container">
        <div class="quiz-header">
            <div class="question-number">Question <?php echo htmlspecialchars($currentQuestion, ENT_QUOTES, 'UTF-8'); ?> of 50</div>
        </div>
        <div class="domain"><?php echo htmlspecialchars($question['domain'], ENT_QUOTES, 'UTF-8'); ?></div>
        <div class="question-box">
            <div class="question-text">
                <?php echo htmlspecialchars($question['question'], ENT_QUOTES, 'UTF-8'); ?>
            </div>
            <?php if (isset($question['details'])): ?>
                <div class="question-details">
                    <p><?php echo htmlspecialchars($question['details'], ENT_QUOTES, 'UTF-8'); ?></p>
                </div>
            <?php endif; ?>
            <form id="quiz-form" method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <div class="options">
                    <?php foreach($question['options'] as $key => $value): ?>
                    <label class="option">
                        <input type="radio" name="answer" value="<?php echo htmlspecialchars($key, ENT_QUOTES, 'UTF-8'); ?>">
                        <span><?php echo htmlspecialchars($key . '. ' . $value, ENT_QUOTES, 'UTF-8'); ?></span>
                    </label>
                    <?php endforeach; ?>
                </div>
            </form>
            <div class="explanation-container" style="display: none;">
                <p class="explanation-text"></p>
                <div class="all-explanations"></div>
            </div>
            <div class="actions">
                <button class="show-answer" style="display: none;">Show Answer</button>
                <div class="next-section">
                    <?php if($currentQuestion > 1): ?>
                        <button class="prev-button">Prev</button>
                    <?php endif; ?>
                    <?php if($currentQuestion < 50): ?>
                        <button class="next-button">Next</button>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        <div class="numbers">
            <?php for($i = 1; $i <= 50; $i++): ?>
                <button class="number <?php echo ($i === $currentQuestion) ? 'active' : ''; ?>" 
                        data-question="<?php echo $i; ?>">
                    <?php echo $i; ?>
                </button>
            <?php endfor; ?>
        </div>
    </main>
    <div class="footer">© 20∞ by <a href="https://www.linkedin.com/in/brennocm/" target="_blank" rel="noopener noreferrer">Brenno M.</a></div>
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        // Implementar verificação de integridade do cliente
        const integrity = {
            currentQuestion: <?php echo $currentQuestion; ?>,
            csrf_token: '<?php echo $_SESSION['csrf_token']; ?>'
        };

        // Função para validar navegação
        function validateNavigation(questionNum) {
            return questionNum >= 1 && questionNum <= 50;
        }

        // Event listeners com validação
        document.querySelectorAll('.number').forEach(btn => {
            btn.addEventListener('click', function(e) {
                e.preventDefault();
                const questionNum = parseInt(this.dataset.question);
                if (validateNavigation(questionNum)) {
                    window.location.href = `?q=${questionNum}`;
                }
            });
        });

        // Prevenção de XSS na exibição de explicações
        function sanitizeHTML(str) {
            const div = document.createElement('div');
            div.textContent = str;
            return div.innerHTML;
        }

        // Resto do código JavaScript existente com melhorias de segurança
        const showAnswerBtn = document.querySelector('.show-answer');
        const options = document.querySelectorAll('.option input');
        const explanationContainer = document.querySelector('.explanation-container');
        const allExplanationsDiv = document.querySelector('.all-explanations');
        const prevButton = document.querySelector('.prev-button');
        const nextButton = document.querySelector('.next-button');


        const correctAnswer = '<?php echo htmlspecialchars($question['correct_answer'], ENT_QUOTES, 'UTF-8'); ?>';
        const allExplanations = <?php echo isset($question['all_explanations']) ? json_encode($question['all_explanations']) : 'null'; ?>;

        // Implementar verificações de segurança adicionais no cliente
        if (typeof correctAnswer !== 'string' || typeof allExplanations !== 'object') {
            console.error('Invalid data type received');
            return;
        }

        options.forEach(option => {
            option.addEventListener('change', function() {
                if (this.value && typeof this.value === 'string') {
                    showAnswerBtn.style.display = 'inline-block';
                }
            });
        });

        showAnswerBtn.addEventListener('click', function() {
            options.forEach(option => {
                option.disabled = true;
                const parentLabel = option.closest('.option');
                if (option.value === correctAnswer) {
                    parentLabel.style.backgroundColor = '#4caf50';
                    parentLabel.style.color = 'white';
                } else if(option.checked) {
                    parentLabel.style.backgroundColor = '#ff5252';
                    parentLabel.style.color = 'white';
                }
            });

            if (allExplanations && typeof allExplanations === 'object') {
                let allExplanationsHTML = '';
                for (const key in allExplanations) {
                    if (allExplanations.hasOwnProperty(key)) {
                        allExplanationsHTML += `<p><strong>${sanitizeHTML(key)}</strong>) ${sanitizeHTML(allExplanations[key])}</p>`;
                    }
                }
                allExplanationsDiv.innerHTML = allExplanationsHTML;
                explanationContainer.style.display = 'block';
            }

            showAnswerBtn.disabled = true;
        });

        //navegacao nos botoes
        if (prevButton) {
            prevButton.addEventListener('click', function () {
               const currentQuestion = <?php echo $currentQuestion; ?>;
                 if (currentQuestion > 1) {
                        window.location.href = `?q=${currentQuestion - 1}`;
                    }
            });
         }

        if (nextButton) {
            nextButton.addEventListener('click', function () {
                const currentQuestion = <?php echo $currentQuestion; ?>;
                 if (currentQuestion < 50) {
                    window.location.href = `?q=${currentQuestion + 1}`;
                }
            });
         }

    });
    </script>
</body>
</html>