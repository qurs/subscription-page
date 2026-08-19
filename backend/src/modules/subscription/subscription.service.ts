import { Request, Response } from 'express'

import { Injectable } from '@nestjs/common'
import { Logger } from '@nestjs/common'

import { TRequestTemplateTypeKeys } from '@remnawave/backend-contract'

import { AxiosService } from '@common/axios/axios.service'
import axios from 'axios'
import { TypedConfigService } from '@common/config/app-config'

@Injectable()
export class SubscriptionService {
	private readonly logger = new Logger(SubscriptionService.name)

	constructor(
		private readonly axiosService: AxiosService,
		private readonly configService: TypedConfigService,
	) {}

	public async serveSubscriptionPage(
		clientIp: string,
		req: Request,
		res: Response,
		shortUuid: string,
		clientType?: TRequestTemplateTypeKeys,
	): Promise<void> {
		try {
			const subscriptionDataResponse =
				await this.axiosService.getSubscription(
					clientIp,
					shortUuid,
					req.headers,
					!!clientType,
					clientType,
				)

			if (!subscriptionDataResponse) {
				res.socket?.destroy()
				return
			}

			if (subscriptionDataResponse.headers) {
				res.set(subscriptionDataResponse.headers)
			}

			if (Array.isArray(subscriptionDataResponse.subscription)) {
				let disabled = false
				for (const item of subscriptionDataResponse.subscription) {
					if (item.remarks == 'UNAVAILABLE') {
						disabled = true
						break
					}
				}

				if (!disabled) {
					const res = await axios.get(
						this.configService.getOrThrow('BONUS_KEYS_URL'),
						{
							headers: {
								'user-agent': 'Remnawave Subscription Page',
								Authorization: `Bearer ${this.configService.getOrThrow('BONUS_KEYS_TOKEN')}`,
							},
							validateStatus: () => true,
						},
					)

					const bonusKeys =
						res.status === 200 && Array.isArray(res.data)
							? res.data
							: []

					let i = 0
					let outbounds: Array<any> = []
					let remarkNumber = 1
					for (const outbound of bonusKeys) {
						outbounds.push(outbound)

						if (
							(i + 1) %
								this.configService.getOrThrow(
									'BONUS_KEYS_COUNT_PER_BALANCER',
								) ==
								0 ||
							i === bonusKeys.length - 1
						) {
							subscriptionDataResponse.subscription.push({
								burstObservatory: {
									pingConfig: {
										connectivity: '',
										destination:
											'http://connectivitycheck.gstatic.com/generate_204',
										interval: '15s',
										sampling: 2,
										timeout: '3s',
									},
									subjectSelector: ['proxy'],
								},

								dns: {
									servers: ['77.88.8.8'],
								},
								inbounds: [
									{
										listen: '127.0.0.1',
										port: 10808,
										protocol: 'socks',
										settings: {
											auth: 'noauth',
											udp: true,
										},
										sniffing: {
											destOverride: [
												'http',
												'tls',
												'quic',
											],
											enabled: true,
											routeOnly: false,
										},
										tag: 'socks',
									},
									{
										listen: '127.0.0.1',
										port: 10809,
										protocol: 'http',
										settings: {
											allowTransparent: false,
										},
										sniffing: {
											destOverride: [
												'http',
												'tls',
												'quic',
											],
											enabled: true,
											routeOnly: false,
										},
										tag: 'http',
									},
								],
								meta: null,
								outbounds: [
									...outbounds,
									{
										protocol: 'freedom',
										tag: 'direct',
									},
									{
										protocol: 'blackhole',
										tag: 'block',
									},
								],
								remarks: `🇪🇺 🏳️-LTE | 🌐 Белые списки #${remarkNumber}`,
								routing: {
									balancers: [
										{
											fallbackTag: 'proxy',
											selector: ['proxy'],
											strategy: {
												settings: {
													baselines: [
														'200ms',
														'500ms',
														'1000ms',
													],
													expected: 1,
													maxRTT: '1.5s',
													tolerance: 0.3,
												},

												type: 'leastLoad',
											},
											tag: 'Super_Balancer',
										},
									],
									domainMatcher: 'hybrid',
									domainStrategy: 'IPIfNonMatch',
									rules: [
										{
											outboundTag: 'direct',
											port: '53',
											type: 'field',
										},
										{
											outboundTag: 'direct',
											protocol: ['bittorrent'],
											type: 'field',
										},
										{
											balancerTag: 'Super_Balancer',
											network: 'tcp,udp',
											type: 'field',
										},
										{
											domain: [
												'https://ipv4-internet.yandex.net/api/v0/ip',
												'https://ipv6-internet.yandex.net/api/v0/ip',
												'https://ifconfig.me/ip',
												'https://api.ipify.org',
												'https://checkip.amazonaws.com',
												'https://ip.mail.ru/',
											],
											outboundTag: 'direct',
											type: 'field',
										},
									],
								},
							})

							outbounds = []
							remarkNumber++
						}
						i++
					}
				}
			}

			res.status(200).send(subscriptionDataResponse.subscription)
			return
		} catch (error) {
			this.logger.error('Error in serveSubscriptionPage', error)

			res.socket?.destroy()
			return
		}
	}
}
