<?php

declare(strict_types=1);

namespace OCA\TwoFactorTOTP\Command;

use Base32\Base32;
use EasyTOTP\Factory;
use EasyTOTP\TOTPValidResultInterface;
use OCA\TwoFactorTOTP\Db\TotpSecret;
use OCA\TwoFactorTOTP\Db\TotpSecretMapper;
use OCA\TwoFactorTOTP\Event\DisabledByAdmin;
use OCA\TwoFactorTOTP\Event\StateChanged;
use OCA\TwoFactorTOTP\Exception\NoTotpSecretFoundException;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\EventDispatcher\IEventDispatcher;
use OCA\Encryption\Util;
use OCP\IConfig;
use OCP\IUser;
use OCP\IUserManager;
use OCP\Security\ICrypto;
use OCP\Security\ISecureRandom;
use OCP\Activity\ISetting;
use OCP\IL10N;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\QuestionHelper;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\Question;

class RecoverTOTP extends Command {

	/** @var Util */
	protected $util;

	/** @var IUserManager */
	protected $userManager;

	/** @var  QuestionHelper */
	protected $questionHelper;

	/** @var TotpSecretMapper */
	private $secretMapper;

	/** @var ICrypto */
	private $crypto;

	/**
	 * @param Util $util
	 * @param IConfig $config
	 * @param IUserManager $userManager
	 * @param QuestionHelper $questionHelper
	 */
	public function __construct(Util $util,
								IConfig $config,
								IUserManager $userManager,
                                QuestionHelper $questionHelper,
                                TotpSecretMapper $secretMapper,
                                ICrypto $crypto) {
		$this->secretMapper = $secretMapper;
		$this->crypto = $crypto;
		$this->util = $util;
		$this->questionHelper = $questionHelper;
		$this->userManager = $userManager;
		parent::__construct();
	}

	protected function configure() {
		$this
			->setName('totp:recover-totp')
			->setDescription('Recover TOTP secret for a user.');

		$this->addArgument(
			'user',
			InputArgument::REQUIRED,
			'user which should be recovered'
		);
	}

	protected function execute(InputInterface $input, OutputInterface $output): int {
		$uid = $input->getArgument('user');
		$userExists = $this->userManager->userExists($uid);
		if ($userExists === false) {
			$output->writeln('User "' . $uid . '" unknown.');
			return 1;
		}
		$user = $this->userManager->get($uid);
        $secret = $this->dumpSecret($user);
        $output->writeln('TOTP Secret: "' . $secret . '"');
        return 0;
    }

    public function dumpSecret(IUser $user): string {
        try {
            $dbSecret = $this->secretMapper->getSecret($user);
        } catch (DoesNotExistException $ex) {
            throw new NoTotpSecretFoundException();
        }

        $secret = $this->crypto->decrypt($dbSecret->getSecret());
        return $secret;
    }
}

?>
